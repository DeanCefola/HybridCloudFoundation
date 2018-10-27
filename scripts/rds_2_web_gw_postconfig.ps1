
#############################################################################
# PowerShell Script to Configure RDS WebAccess in HA Mode#
#############################################################################

Param (
    [String] $webAccessServer1,
    [String] $webAccessServer2,
    [String] $DomainFQDN,       
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $BrokerServer,
    [String] $DC2VMName,
    [String] $DC1VMName,
    [String] $ConnectionBrokerLBDNSIP,
    [String] $WebAccessLBDNSIP,
    [String] $WebAccessLBDNSName,
    [String] $ConnectionBrokerLBDNSName,
    [String] $DFS1Hostname,
    [String] $DFS2Hostname,
    [String] $DFSSharePath,
    [String] $DFSRootPath,
    [String] $RDSComputersSecurityGroup
)
$secpasswd = ConvertTo-SecureString $Adminuserpassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$Adminusername@$DomainFQDN", $secpasswd)

#####################################################
# PowerShell Script to Generate Machine Keys for IIS#
#####################################################

# genrate 64 and 24 char keys:
[int]$keylen = 64
       $buff = new-object "System.Byte[]" $keylen
       $rnd = new-object System.Security.Cryptography.RNGCryptoServiceProvider
       $rnd.GetBytes($buff)
       $result =""
       for($i=0; $i -lt $keylen; $i++)  {
             $result += [System.String]::Format("{0:X2}",$buff[$i])
       }
       $validationkey64 = $result
       # Write-Host $validationkey64
       # end of Validation Key code
       $keylen = 24
       $buff1 = new-object "System.Byte[]" $keylen
       $rnd1 = new-object System.Security.Cryptography.RNGCryptoServiceProvider
       $rnd1.GetBytes($buff1)
       $result =""
       for($i=0; $i -lt $keylen; $i++)  {
             $result += [System.String]::Format("{0:X2}",$buff[$i])
       }
       $decryptionKey24 = $result
       # Write-Host $decryptionKey24
# logic end for 64 and 24 char keys

#################################################################
# PowerShell Script to Enable and Set the permission for CredSSP#
#################################################################

#Enable CredSSP
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

##########################################################################
# PowerShell Script to Configure RDS Web Access Server Node 2#
##########################################################################

$s = New-PSSession -ComputerName "$webAccessServer2.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s -ArgumentList $webAccessServer1, $webAccessServer2, $DomainFQDN, $Adminusername, $Adminuserpassword, $BrokerServer, $validationkey64, $decryptionKey24 -ScriptBlock {
Param (
    [String] $webAccessServer1,
    [String] $webAccessServer2,
    [String] $DomainFQDN,       
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $BrokerServer,
    [String] $validationkey64,
    [String] $decryptionKey24 
)
    #Check RDS WebAccess Server
    $RDSWebAccesServercheck = Get-RDServer -ConnectionBroker "$BrokerServer.$DomainFQDN" -Role RDS-WEB-ACCESS
    if ($RDSWebAccesServercheck.Server -eq "$webAccessServer2.$DomainFQDN" ) {
        Write-Output "RDS WebAccess Server $webAccessServer2 is already part of the Deployment"        
    }
    else {        
        #Add RDS WebAccess Server
        Write-Output "RDS WebAccess Server $webAccessServer2 is not part of the Deployment, Adding....."
        Add-RDServer -Server "$webAccessServer2.$DomainFQDN" -Role RDS-WEB-ACCESS -ConnectionBroker "$BrokerServer.$DomainFQDN" -Verbose
    }
    sleep 10
    #Confiure Machine Key for RDweb 
    function ValidateWindowsFeature {
    $localhost = $webAccessServer2
    $RdsWindowsFeature = Get-WindowsFeature -ComputerName $localhost -Name RDS-Web-Access     
    if ($RdsWindowsFeature.InstallState -eq "Installed") {
        Return $true
    }
    else {
        Return $false
    }
}
    $Validationheck = $False
    $Validationheck = ValidateWindowsFeature
    $localhost = $webAccessServer2
    if($Validationheck -eq $true) {
        Write-Host "Windows feature RDS-Web_access present on $($localhost)"
        $machineConfig = "C:\Windows\Web\RDWeb\Web.config"
       if (Test-Path $machineConfig) {
        Write-Host "editing machine config file : $($machineConfig) on server $($localhost) "        
        try {
        $xml = [xml](get-content $machineConfig)
        $xml.Save($machineConfig + "_")        
        $root = $xml.get_DocumentElement()
        $system_web = $root."system.web"
        if ($system_web.machineKey -eq $null) { 
            $machineKey = $xml.CreateElement("machineKey") 
            $a = $system_web.AppendChild($machineKey)
        }
        $system_web.SelectSingleNode("machineKey").SetAttribute("validationKey","$validationKey64")
        $system_web.SelectSingleNode("machineKey").SetAttribute("decryptionKey","$decryptionKey24")
        $a = $xml.Save($machineConfig)        
        }
        Catch {
            Write-Host $Error
        }        
        } # end of If test-path
}
    else {
        Write-Host "Windows feature RDS-Web_access is not present on $($localhost)"
    }
    #Reset IIS
    IISreset
}
Remove-PSSession $s

##########################################################################
# PowerShell Script to Enable CredSSP on RDS WebAccess Node 1#
##########################################################################

$s1 = New-PSSession -ComputerName "$webAccessServer1.$DomainFQDN" -Credential $cred
Invoke-Command -Session $s1 -ScriptBlock {
    Enable-WSManCredSSP -Role server -Force
    #Enable PS Remoting
    winrm set winrm/config/client/auth '@{Basic="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
    winrm set winrm/config/client '@{AllowUnencrypted="true"}'
    Set-Item wsman:\localhost\client\trustedhosts *.$DomainFQDN -Force
} -ArgumentList $DomainFQDN
Remove-PSSession $s1

##########################################################################
# PowerShell Script to Configure Machine Key on RDS WebAccess Node 1#
##########################################################################
$s2 = New-PSSession -ComputerName "$webAccessServer1.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s2 -ArgumentList $webAccessServer1, $webAccessServer2, $DomainFQDN, $Adminusername, $Adminuserpassword, $BrokerServer, $validationkey64, $decryptionKey24 -ScriptBlock {
Param (
    [String] $webAccessServer1,
    [String] $webAccessServer2,
    [String] $DomainFQDN,       
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $BrokerServer,
    [String] $validationkey64,
    [String] $decryptionKey24 
)
    #Configure Machine Key
    function ValidateWindowsFeature {
        $localhost = $webAccessServer1
        $RdsWindowsFeature = Get-WindowsFeature -ComputerName $localhost -Name RDS-Web-Access     
        if ($RdsWindowsFeature.InstallState -eq "Installed") {
            Return $true
        }
        else {
            Return $false
        }
    }
    $Validationheck = $False
    $Validationheck = ValidateWindowsFeature
    $localhost = $webAccessServer1
    if($Validationheck -eq $true) {
        Write-Host "Windows feature RDS-Web_access present on $($localhost)"
        $machineConfig = "C:\Windows\Web\RDWeb\Web.config"
        if (Test-Path $machineConfig) {
            Write-Host "editing machine config file : $($machineConfig) on server $($localhost) "        
            try {
                $xml = [xml](get-content $machineConfig)
                $xml.Save($machineConfig + "_")        
                $root = $xml.get_DocumentElement()
                $system_web = $root."system.web"
                if ($system_web.machineKey -eq $null) { 
                    $machineKey = $xml.CreateElement("machineKey") 
                    $a = $system_web.AppendChild($machineKey)
                }
                $system_web.SelectSingleNode("machineKey").SetAttribute("validationKey","$validationKey64")
                $system_web.SelectSingleNode("machineKey").SetAttribute("decryptionKey","$decryptionKey24")
                $a = $xml.Save($machineConfig)        
                }
            Catch {
                Write-Host $Error
            }        
        } # end of If test-path
    }
    else {
        Write-Host "Windows feature RDS-Web_access is not present on $($localhost)"
    }
    #Reset IIS
    IISreset
}
Remove-PSSession $s2

##########################################################################
# PowerShell Script to Enable CredSSP on DC Node 2                       #
##########################################################################

$s3 = New-PSSession -ComputerName "$DC2VMName.$DomainFQDN" -Credential $cred
Invoke-Command -Session $s3 -ScriptBlock {
    Enable-WSManCredSSP -Role server -Force
    #Enable PS Remoting
    winrm set winrm/config/client/auth '@{Basic="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
    Set-Item wsman:\localhost\client\trustedhosts *.$DomainFQDN -Force
} -ArgumentList $DomainFQDN
Remove-PSSession $s3

##########################################################################
# PowerShell Script to Create DNS Records and Security Group on DC Node 2#
##########################################################################

$s4 = New-PSSession -ComputerName "$DC2VMName.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s4 -ArgumentList $DomainFQDN, $ConnectionBrokerLBDNSIP, $WebAccessLBDNSIP, $WebAccessLBDNSName, $ConnectionBrokerLBDNSName, $DC1VMName, $RDSComputersSecurityGroup -ScriptBlock {
Param (
    [String] $DomainFQDN,       
    [String] $ConnectionBrokerLBDNSIP,
    [String] $WebAccessLBDNSIP,
    [String] $WebAccessLBDNSName,
    [String] $ConnectionBrokerLBDNSName,
    [String] $DC1VMName,
    [String] $RDSComputersSecurityGroup
)
    $cbdnschk = $NULL
    $cbdnsexist =$NULL
    $ErrorActionPreference= "silentlycontinue"
    $cbdnschk = [System.Net.DNS]::GetHostAddresses("$ConnectionBrokerLBDNSName")
    $cbdnsip = $cbdnschk.IPAddressToString 
    if ($cbdnsip -ne $NULL) {
        $cbdnsexist = "true"
    } 
    else {
        $cbdnsexist = "false"
    }
    $cbdnsexist
    if ($cbdnsexist -eq "true") {
        Write-Host "DNS 'A' record $ConnectionBrokerLBDNSName already exists"
    }
    else {
        Add-DnsServerResourceRecordA -Name $ConnectionBrokerLBDNSName -ZoneName $DomainFQDN -AllowUpdateAny -IPv4Address $ConnectionBrokerLBDNSIP -TimeToLive 01:00:00
    }
    $wadnschk = $NULL
    $wadnsexist =$NULL
    $ErrorActionPreference= "silentlycontinue"
    $wadnschk = [System.Net.DNS]::GetHostAddresses("$WebAccessLBDNSName")
    $wadnsip = $wadnschk.IPAddressToString 
    if ($wadnsip -ne $NULL) {
        $wadnsexist = "true"
    } 
    else {
        $wadnsexist = "false"
    }
    $wadnsexist
    if ($wadnsexist -eq "true") {
        Write-Host "DNS 'A' record $WebAccessLBDNSName already exists"
    }
    else {
        Add-DnsServerResourceRecordA -Name $WebAccessLBDNSName -ZoneName $DomainFQDN -AllowUpdateAny -IPv4Address $WebAccessLBDNSIP -TimeToLive 01:00:00
    }
    sleep 5
    if (Get-ADGroup -Filter {SamAccountName -eq $RDSComputersSecurityGroup}) {
        Write-Output "Group already exists"
    }
    else {
        New-ADGroup -Name $RDSComputersSecurityGroup -groupScope domainlocal
    }
    #Add all RDS Computers as members into this group
    $RDSComputers = Get-ADComputer -Filter * | Where-Object {$_.Name -like "*RDS*"}
    Add-ADGroupMember -Identity $RDSComputersSecurityGroup -Members $RDSComputers
    sleep 10
    #Initiate Force Active Directory Replication
    repadmin /syncall /force /A /e /q $DC1VMName 
    sleep 10
}
Remove-PSSession $s4

#####################################################################################
# PowerShell Script to Grant Share Permission to RDSComputers Security Group on DFS1#
#####################################################################################

$s5 = New-PSSession -ComputerName "$DFS1Hostname.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s5 -ArgumentList $DFSRootPath, $DFSSharePath, $DomainFQDN, $RDSComputersSecurityGroup -ScriptBlock {
Param (
    [String] $DFSRootPath,
    [String] $DFSSharePath,
    [String] $DomainFQDN,
    [String] $RDSComputersSecurityGroup
)
    #FlushDNS
    ipconfig /flushdns
    sleep 10
    #Create the SMB share folders:
    $folders = @("$DFSRootPath","$DFSSharePath")
    foreach($folder in $folders) {
        $foldercheck = Test-Path -Path $folder    
        if ($foldercheck -ne "True") {
            #Create Folders
            Write-Output "$folder does not exists, Creating $folder ..."
            New-Item -ItemType directory -Path $folder
        }
        else {
            Write-Output "$folder already exists"
        }
        #Assign Permission to RDS All Computers on DFS shares
        $folder | ForEach-Object {$sharename = (Get-Item $_).name; Grant-SmbShareAccess -Name $shareName -AccountName "$DomainFQDN\$RDSComputersSecurityGroup" -AccessRight Full -Force}
    }
}
Remove-PSSession $s5

#####################################################################################
# PowerShell Script to Grant Share Permission to RDSComputers Security Group on DFS2#
#####################################################################################

$s6 = New-PSSession -ComputerName "$DFS2Hostname.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s6 -ArgumentList $DFSRootPath, $DFSSharePath, $DomainFQDN, $RDSComputersSecurityGroup -ScriptBlock {
Param (
    [String] $DFSRootPath,
    [String] $DFSSharePath,
    [String] $DomainFQDN,
    [String] $RDSComputersSecurityGroup
)
    #FlushDNS
    ipconfig /flushdns
    sleep 10
    #Create the SMB share folders:
    $folders = @($DFSRootPath,$DFSSharePath)
    foreach($folder in $folders) {
        $foldercheck = Test-Path -Path $folder    
        if ($foldercheck -ne "True") {
            #Create Folders
            Write-Output "$folder does not exists, Creating $folder ..."
            New-Item -ItemType directory -Path $folder
        }
        else {
            Write-Output "$folder already exists"
        }        
        #Assign Permission to RDS All Computers on DFS shares
        $folder | ForEach-Object {$sharename = (Get-Item $_).name; Grant-SmbShareAccess -Name $shareName -AccountName "$DomainFQDN\$RDSComputersSecurityGroup" -AccessRight Full -Force}
    }
}
Remove-PSSession $s6

###############################
#End of Script
###############################
