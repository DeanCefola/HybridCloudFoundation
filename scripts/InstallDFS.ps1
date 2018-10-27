##################################################
# PowerShell Script to Fully Configure 2 Node DFS#
##################################################
Param (
	[String] $DFS0Hostname,
	[String] $DFS1Hostname,
	[String] $Adminusername,
	[String] $Adminuserpassword,
	[String] $DomainFQDN,
	[String] $DFSRootPath,
	[String] $DFSNamespaceFolderName,
	[String] $DFSNamespaceShareName,
	[String] $DFSReplicationGroupName,
	[String] $DFSSharePath
)

$secpasswd = ConvertTo-SecureString $Adminuserpassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$Adminusername@$DomainFQDN", $secpasswd)


####################################################
#                Setup Local Logging               #
####################################################
$LocalPath = 'C:\InstallDFS'
$LocalFile = "$LocalPath\InstallDFS.log"
if ((Test-Path -path $LocalPath) -ne $true) {       
    New-Item -ItemType Directory  $LocalPath
} 
if ((Test-Path -path $LocalFile) -ne $true) {       
    New-Item -ItemType File $LocalFile
}
Add-Content $LocalFile "DFS Server 0 - $DFS0Hostname"
Add-Content $LocalFile "DFS Server 1 - $DFS1Hostname"
Add-Content $LocalFile "Admin Name - $Adminusername"
Add-Content $LocalFile "Admin Password - $Adminuserpassword"
Add-Content $LocalFile "Domain FQDN - $DomainFQDN"
Add-Content $LocalFile "DFS Root Path - $DFSRootPath"
Add-Content $LocalFile "DFS NameSpace - $DFSNamespaceFolderName"
Add-Content $LocalFile "DFS ShareName - $DFSNamespaceShareName"
Add-Content $LocalFile "DFS RepGroup - $DFSReplicationGroupName"
Add-Content $LocalFile "DFS SharePath - $DFSSharePath"
Add-Content $LocalFile "InstallDFS Command -- \InstallDFS.ps1 `
    -DFS0Hostname $DFS0Hostname `
    -DFS1Hostname $DFS1Hostname `
    -Adminusername $Adminusername `
    -Adminuserpassword $Adminuserpassword `
    -DomainFQDN $DomainFQDN `
    -DFSRootPath $DFSRootPath `
    -DFSNamespaceFolderName $DFSNamespaceFolderName `
    -DFSNamespaceShareName $DFSNamespaceShareName `
    -DFSReplicationGroupName $DFSReplicationGroupName `
    -DFSSharePath $DFSSharePath "
Start-Transcript -LiteralPath $LocalFile

      
####################################################
# PowerShell Script to Enable CredSSP#
####################################################
get-DnsClient | Where-Object -Property InterfaceAlias -Match ethernet `
    | Set-DnsClient -ConnectionSpecificSuffix $DomainFQDN
Enable-WSManCredSSP -Role server -Force
Enable-WSManCredSSP -Role Client -DelegateComputer * -Force
$allowed = @("WSMAN/*.$DomainFQDN")
$key = 'hklm:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
if (!(Test-Path $key)) {
    md $key
}
New-ItemProperty -Path $key -Name AllowFreshCredentials -Value 1 -PropertyType Dword -Force            

$key = Join-Path $key 'AllowFreshCredentials'
if (!(Test-Path $key)) {
    md $key
}
$i = 1
$allowed |% {
    # Script does not take into account existing entries in this key
    New-ItemProperty -Path $key -Name $i -Value $_ -PropertyType String -Force
    $i++
}
#Enable PS Remoting
winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/client '@{AllowUnencrypted="true"}'
Set-Item wsman:\localhost\client\trustedhosts *.$DomainFQDN -Force
Restart-Service WinRM
sleep 5


####################################################
# PowerShell Script to Initialize Data Disk on DFS0#
####################################################
$newdisk = get-disk | Where-Object partitionstyle -eq 'raw'
foreach($d in $newdisk) {
    $disknum = $d.Number
    $dl = get-Disk $d.Number | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize
    Start-Sleep 10
    Format-Volume -DriveLetter F -FileSystem NTFS -NewFileSystemLabel "DataDisk1" -Confirm:$false
}


#################################################
# PowerShell Script to Install DFS Roles on DFS0#
#################################################
#List of Roles to be installed. If more than one, use comma separated list
$Featurename = "FS-DFS-Namespace", "FS-DFS-Replication", "RSAT-DFS-Mgmt-Con"
#For each feature, check if the feature is installed or not
foreach($Feature in $Featurename) {
    $check = Get-WindowsFeature -Name $Feature    
    if ($check.installed -ne "True") {
        #Install the feature if not installed as well as management tools
        Write-Output "Windows Feature $Feature not installed. Installing $Feature ..."
        $Install= Add-WindowsFeature $Feature -IncludeManagementTools        
    }
    else {
        Write-Output "Feature $Feature is already installed"
    }
}


####################################################
# PowerShell Script to Initialize Data Disk on DFS1#
####################################################
$s1 = New-PSSession `
    -ComputerName "$DFS1Hostname.$DomainFQDN" `
    -Credential $cred
Invoke-Command -Session $s1 -ScriptBlock {
    $newdisk = get-disk | Where-Object partitionstyle -eq 'raw'
    foreach($d in $newdisk) {
        $disknum = $d.Number
        $dl = get-Disk $d.Number | Initialize-Disk -PartitionStyle MBR -PassThru | New-Partition -AssignDriveLetter -UseMaximumSize
        Start-Sleep 10
        Format-Volume -DriveLetter F -FileSystem NTFS -NewFileSystemLabel "DataDisk1" -Confirm:$false
    }
}


#################################################
# PowerShell Script to Install DFS Roles on DFS1#
#################################################
Invoke-Command -Session $s1 -ScriptBlock {
#List of Roles to be installed. If more than one, use comma separated list
$Featurename = "FS-DFS-Namespace", "FS-DFS-Replication", "RSAT-DFS-Mgmt-Con"
#For each feature, check if the feature is installed or not
    foreach($Feature in $Featurename){
        $check = Get-WindowsFeature -Name $Feature    
        if ($check.installed -ne "True") {
            #Install the feature if not installed as well as management tools
            Write-Output "Windows Feature $Feature not installed. Installing $Feature ..."        
            $Install= Add-WindowsFeature $Feature -IncludeManagementTools        
        }       
        else {
            Write-Output "Feature $Feature is already installed"
        }
    }
}


#################################################
# PowerShell Script to Enable CredSSP#
#################################################
$Command = {        
    $DomainFQDN = $($Args[0])
    ""
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Force
    ""
    write $DomainFQDN
    get-DnsClient | Where-Object -Property InterfaceAlias -Match ethernet `
        | Set-DnsClient -ConnectionSpecificSuffix $DomainFQDN
    Enable-WSManCredSSP -Role server -Force
    #Enable PS Remoting
    winrm set winrm/config/client/auth '@{Basic="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
    winrm set winrm/config/client '@{AllowUnencrypted="true"}'
    Set-Item wsman:\localhost\client\trustedhosts *.$DomainFQDN -Force 
}
 Invoke-Command `
    -Session $s1 `
    -ScriptBlock $Command `
    -ArgumentList $DomainFQDN
Remove-PSSession $s1


###################################################
# PowerShell Script to Configure Namespace on DFS0#
###################################################
$s2 = New-PSSession -ComputerName "$DFS0Hostname.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s2 -ArgumentList $DFS0Hostname, $DFS1Hostname, $Adminusername, $Adminuserpassword, $DomainFQDN, $DFSRootPath, $DFSNamespaceFolderName, $DFSNamespaceShareName, $DFSReplicationGroupName, $DFSSharePath -ScriptBlock {
Param (
    [String] $DFS0Hostname,
    [String] $DFS1Hostname,
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $DomainFQDN,
    [String] $DFSRootPath,
    [String] $DFSNamespaceFolderName,
    [String] $DFSNamespaceShareName,
    [String] $DFSReplicationGroupName,
    [String] $DFSSharePath
)
    #Create the SMB share folders:
    $folders = @("$DFSRootPath","$DFSSharePath")
    foreach($folder in $folders) {
        $foldercheck = Test-Path -Path $folder    
        if ($foldercheck -ne "True") {
            #Create Folders
            Write-Output "$folder does not exists, Creating $folder ..."
            New-Item -ItemType directory -Path $folder        
            #Create the shares
            $folder | ForEach-Object {$sharename = (Get-Item $_).name; New-SMBShare -Name $shareName -Path $_ -FullAccess Administrators -ReadAccess Everyone}
        }
        else {
            Write-Output "$folder already exists"
        }
    } 
    #Check DFS Root
    $DFSRootcheck = Get-DfsnRoot -Domain $DomainFQDN
    if ($DFSRootcheck.Path -eq "\\$DomainFQDN\$DFSNamespaceFolderName" ) {
        Write-Output "DFS Root already exists"        
    }
    else {        
        #Create the DFS Root
        Write-Output "DFSRoot does not exists, Creating a new ..."
        New-DfsnRoot -Path "\\$DomainFQDN\$DFSNamespaceFolderName" -TargetPath "\\$DFS0Hostname\$DFSNamespaceFolderName" -Type DomainV2 -EnableAccessBasedEnumeration $true
        #Create the DFS Folders for DFS1
        $folder | Where-Object {$_ -like "*shares*"} | ForEach-Object {$name = (Get-Item $_).name; $DfsPath = "\\$DomainFQDN\$DFSNamespaceFolderName\$name"; $targetPath = "\\$DFS0Hostname\$name";New-DfsnFolderTarget -Path $dfsPath -TargetPath $targetPath}
    } 
}
Remove-PSSession $s2


###################################################
# PowerShell Script to Configure Namespace on DFS1#
###################################################
$s3 = New-PSSession -ComputerName "$DFS1Hostname.$DomainFQDN" -Credential $cred
Invoke-Command -Session $s3 -ArgumentList $DFS0Hostname, $DFS1Hostname, $Adminusername, $Adminuserpassword, $DomainFQDN, $DFSRootPath, $DFSNamespaceFolderName, $DFSNamespaceShareName, $DFSReplicationGroupName, $DFSSharePath -ScriptBlock {
Param (
    [String] $DFS0Hostname,
    [String] $DFS1Hostname,
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $DomainFQDN,
    [String] $DFSRootPath,
    [String] $DFSNamespaceFolderName,
    [String] $DFSNamespaceShareName,
    [String] $DFSReplicationGroupName,
    [String] $DFSSharePath
)
    #Create the SMB share folders:
    $folders = @("$DFSRootPath","$DFSSharePath")
    foreach($folder in $folders) {
        $foldercheck = Test-Path -Path $folder    
        if ($foldercheck -ne "True") {
            #Create Folders
            Write-Output "$folder does not exists, Creating $folder ..."
            New-Item -ItemType directory -Path $folder        
            #Create the shares
            $folder | ForEach-Object {$sharename = (Get-Item $_).name; New-SMBShare -Name $shareName -Path $_ -FullAccess Administrators -ReadAccess Everyone}
        }
        else {
            Write-Output "$folder already exists"
        }
    }
}
Remove-PSSession $s3


#####################################################
# PowerShell Script to Configure Replication on DFS0#
#####################################################
$s4 = New-PSSession -ComputerName "$DFS0Hostname.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s4 -ArgumentList $DFS0Hostname, $DFS1Hostname, $Adminusername, $Adminuserpassword, $DomainFQDN, $DFSRootPath, $DFSNamespaceFolderName, $DFSNamespaceShareName, $DFSReplicationGroupName, $DFSSharePath -ScriptBlock {
Param (
    [String] $DFS0Hostname,
    [String] $DFS1Hostname,
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $DomainFQDN,
    [String] $DFSRootPath,
    [String] $DFSNamespaceFolderName,
    [String] $DFSNamespaceShareName,
    [String] $DFSReplicationGroupName,
    [String] $DFSSharePath
)
    #Check DFS Root
    $DFSRootTargetcheck = Get-DfsnRootTarget -Path "\\$DomainFQDN\$DFSNamespaceFolderName"
    if ($DFSRootTargetcheck.TargetPath -eq "\\$DFS1Hostname\$DFSNamespaceFolderName") {
        Write-Output "DFSRootTarget already exists"
    }
    else {
        #Create the DFS Root Target
        Write-Output "DFSRootTarget does not exists, Creating a new ..."
        New-DfsnRootTarget -Path "\\$DomainFQDN\$DFSNamespaceFolderName" -TargetPath "\\$DFS1Hostname\$DFSNamespaceFolderName"
        #Add Replication Group Name, folder, memebers and connections for Share
        New-DfsReplicationGroup -GroupName $DFSReplicationGroupName -DomainName $DomainFQDN
        New-DfsReplicatedFolder -FolderName $DFSNamespaceShareName -GroupName $DFSReplicationGroupName -DfsnPath "\\$DomainFQDN\$DFSNamespaceFolderName\$DFSNamespaceShareName" -DomainName $DomainFQDN
        Add-DfsrMember -ComputerName $DFS0Hostname,$DFS1Hostname -DomainName $DomainFQDN -GroupName $DFSReplicationGroupName
        Add-DfsrConnection -GroupName $DFSReplicationGroupName -SourceComputerName $DFS0Hostname -DestinationComputerName $DFS1Hostname -DomainName $DomainFQDN
        Start-Sleep 10
        Set-DfsrMembership -GroupName $DFSReplicationGroupName -FolderName $DFSNamespaceShareName -ComputerName $DFS0Hostname -ContentPath "$DFSSharePath" -StagingPathQuotaInMB 20480 -ConflictAndDeletedQuotaInMB 10240 -PrimaryMember $true -Force -DomainName $DomainFQDN
        Set-DfsrMembership -GroupName $DFSReplicationGroupName -FolderName $DFSNamespaceShareName -ComputerName $DFS1Hostname -ContentPath "$DFSSharePath" -StagingPathQuotaInMB 20480 -ConflictAndDeletedQuotaInMB 10240 -Force -DomainName $DomainFQDN
        Start-Sleep 10
        Update-DfsrConfigurationFromAD -ComputerName $DFS0Hostname
        Start-Sleep 20
        dfsrdiag syncnow /partner:$DFS1Hostname /RGName:$DFSReplicationGroupName /Time:1
    }
}
Remove-PSSession $s4


#####################
#End of Script
#####################
