
#############################################################################
# PowerShell Script to Configure RDS Connection Broker in HA Mode#
#############################################################################

Param (
    [String] $AzureSqlName,
    [String] $AzureDatabaseName,
    [String] $SQLUid,
    [String] $SQLPassword,
    [String] $DomainFQDN,
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $BrokerServer,
    [String] $NewBrokerServer,
    [String] $ConnectionBrokerLBDNSName
)

$secpasswd = ConvertTo-SecureString $Adminuserpassword -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("$Adminusername@$DomainFQDN", $secpasswd)
$ODBCDriverocation = "https://download.microsoft.com/download/D/5/E/D5EEF288-A277-45C8-855B-8E2CB7E25B96/x64/msodbcsql.msi"
$SQLNativeClientLocation = "http://go.microsoft.com/fwlink/?LinkID=239648&clcid=0x409"

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

########################################################################################
# PowerShell Script to Install ODBC Driver and SQL Native Client on Connection Broker 1#
########################################################################################

$s = New-PSSession -ComputerName "$BrokerServer.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s -ArgumentList $AzureSqlName, $AzureDatabaseName, $SQLUid, $SQLPassword, $DomainFQDN, $Adminusername, $Adminuserpassword, $BrokerServer, $NewBrokerServer, $ConnectionBrokerLBDNSName, $ODBCDriverocation, $SQLNativeClientLocation -ScriptBlock {
Param (
    [String] $AzureSqlName,
    [String] $AzureDatabaseName,
    [String] $SQLUid,
    [String] $SQLPassword,
    [String] $DomainFQDN,
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $BrokerServer,
    [String] $NewBrokerServer,
    [String] $ConnectionBrokerLBDNSName,
    [String] $ODBCDriverocation,
    [String] $SQLNativeClientLocation
)
    #Check ODBC Driver availability
    $ODBCFileCheck = Test-Path "C:\Packages\Plugins\msiexec.msi"
    if ($ODBCFileCheck -eq "true") {
        Write-Output "ODBC Driver already exists at the path"
    }
    else {
        Invoke-WebRequest -Uri $ODBCDriverocation -OutFile "C:\Packages\Plugins\msiexec.msi"
    }
        #Check SQL Native Client availability
        $SqlncliCheck = Test-Path "C:\Packages\Plugins\sqlncli.msi"
    if ($SqlncliCheck -eq "true") {
        Write-Output "SQL Native Client already exists at the path"
    }
    else {
        Invoke-WebRequest -Uri $SQLNativeClientLocation -OutFile "C:\Packages\Plugins\sqlncli.msi"
        sleep 15
    }
    cd C:\Packages\Plugins\
    $ODBCInstall = msiexec.exe /quiet /passive /qn /i msiexec.msi IACCEPTMSODBCSQLLICENSETERMS=YES ADDLOCAL=ALL
    sleep 15
    $checksqlnClient = Get-ChildItem 'HKLM:\Software\Microsoft\*' -ea SilentlyContinue | Where {$_.name -like '*Client*'}
    if ($checksqlnClient.name.Split('\') -eq 'Microsoft SQL Server Native Client 11.0') {
    Write-Output "SQL native client is already installed"
    }
    else {
    Write-Output "SQL native client is not installed......Installing"
    msiexec.exe /quiet /passive /qn /i sqlncli.msi IACCEPTSQLNCLILICENSETERMS=YES
    }
    sleep 10
    $DoublechecksqlnClient = Get-ChildItem 'HKLM:\Software\Microsoft\*' -ea SilentlyContinue | Where {$_.name -like '*Client*'}
    if ($DoublechecksqlnClient.name.Split('\') -eq 'Microsoft SQL Server Native Client 11.0') {
        Write-Output "SQL native client is already installed"
    }
    else {
        Write-Output "SQL native client is not installed......Installing"
        msiexec.exe /quiet /passive /qn /i sqlncli.msi IACCEPTSQLNCLILICENSETERMS=YES
    }
}
Remove-PSSession $s

##########################################################################
# PowerShell Script to Enable CredSSP on Connection Broker 2#
##########################################################################

$s1 = New-PSSession -ComputerName "$NewBrokerServer.$DomainFQDN" -Credential $cred
Invoke-Command -Session $s1 -ScriptBlock {
    Enable-WSManCredSSP -Role server -Force
    #Enable PS Remoting
    winrm set winrm/config/client/auth '@{Basic="true"}'
    winrm set winrm/config/service/auth '@{Basic="true"}'
    winrm set winrm/config/service '@{AllowUnencrypted="true"}'
    winrm set winrm/config/client '@{AllowUnencrypted="true"}'
    Set-Item wsman:\localhost\client\trustedhosts *$DomainFQDN -Force
}
Remove-PSSession $s1

########################################################################################
# PowerShell Script to Install ODBC Driver and SQL Native Client on Connection Broker 2#
########################################################################################

$s2 = New-PSSession -ComputerName "$NewBrokerServer.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s2 -ArgumentList $AzureSqlName, $AzureDatabaseName, $SQLUid, $SQLPassword, $DomainFQDN, $Adminusername, $Adminuserpassword, $BrokerServer, $NewBrokerServer, $ConnectionBrokerLBDNSName, $ODBCDriverocation, $SQLNativeClientLocation -ScriptBlock {
Param (
    [String] $AzureSqlName,
    [String] $AzureDatabaseName,
    [String] $SQLUid,
    [String] $SQLPassword,
    [String] $DomainFQDN,
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $BrokerServer,
    [String] $NewBrokerServer,
    [String] $ConnectionBrokerLBDNSName,
    [String] $ODBCDriverocation,
    [String] $SQLNativeClientLocation
)
    #Check ODBC Driver availaility
    $ODBCFileCheck = Test-Path "C:\Packages\Plugins\msiexec.msi"
    if ($ODBCFileCheck -eq "true") {
        Write-Output "ODBC Driver already exists at the path"
    }
    else {
        Invoke-WebRequest -Uri $ODBCDriverocation -OutFile "C:\Packages\Plugins\msiexec.msi"
    }
    #Check SQL Native Client availability
    $SqlncliCheck = Test-Path "C:\Packages\Plugins\sqlncli.msi"
    if ($SqlncliCheck -eq "true") {
        Write-Output "SQL Native Client already exists at the path"
    }
    else {
        Invoke-WebRequest -Uri $SQLNativeClientLocation -OutFile "C:\Packages\Plugins\sqlncli.msi"
        sleep 15
    }
    cd C:\Packages\Plugins\
    $ODBCInstall = msiexec.exe /quiet /passive /qn /i msiexec.msi IACCEPTMSODBCSQLLICENSETERMS=YES ADDLOCAL=ALL
    sleep 15
    $checksqlnClient = Get-ChildItem 'HKLM:\Software\Microsoft\*' -ea SilentlyContinue | Where {$_.name -like '*Client*'}

    if ($checksqlnClient.name.Split('\') -eq 'Microsoft SQL Server Native Client 11.0'){
    Write-Output "SQL native client is already installed"
    }
    else{
    Write-Output "SQL native client is not installed......Installing"
    msiexec.exe /quiet /passive /qn /i sqlncli.msi IACCEPTSQLNCLILICENSETERMS=YES
    }
    sleep 10
    $DoublechecksqlnClient = Get-ChildItem 'HKLM:\Software\Microsoft\*' -ea SilentlyContinue | Where {$_.name -like '*Client*'}
    if ($DoublechecksqlnClient.name.Split('\') -eq 'Microsoft SQL Server Native Client 11.0') {
        Write-Output "SQL native client is already installed"
    }
    else {
        Write-Output "SQL native client is not installed......Installing"
        msiexec.exe /quiet /passive /qn /i sqlncli.msi IACCEPTSQLNCLILICENSETERMS=YES
    }
}
Remove-PSSession $s2

########################################################################################
# PowerShell Script to Configure Broker High Availability on Connection Broker 1#
########################################################################################

$s3 = New-PSSession -ComputerName "$BrokerServer.$DomainFQDN" -Credential $cred -Authentication Credssp
Invoke-Command -Session $s3 -ArgumentList $AzureSqlName, $AzureDatabaseName, $SQLUid, $SQLPassword, $DomainFQDN, $Adminusername, $Adminuserpassword, $BrokerServer, $NewBrokerServer, $ConnectionBrokerLBDNSName, $ODBCDriverocation, $SQLNativeClientLocation -ScriptBlock {
Param (
    [String] $AzureSqlName,
    [String] $AzureDatabaseName,
    [String] $SQLUid,
    [String] $SQLPassword,
    [String] $DomainFQDN,
    [String] $Adminusername,
    [String] $Adminuserpassword,
    [String] $BrokerServer,
    [String] $NewBrokerServer,
    [String] $ConnectionBrokerLBDNSName,
    [String] $ODBCDriverocation,
    [String] $SQLNativeClientLocation
)
    Import-Module remotedesktop
    #Check Broker High Availability
    $CheckBrokerHA = Get-RDConnectionBrokerHighAvailability -ConnectionBroker "$BrokerServer.$DomainFQDN"
    if ($CheckBrokerHA -eq $null) {
        #Configure High Availabilty for Broker Server
        Set-RDConnectionBrokerHighAvailability -ConnectionBroker "$BrokerServer.$DomainFQDN" -DatabaseConnectionString "Driver={ODBC Driver 13 for SQL Server};Server=tcp:$AzureSqlName,1433;Database=$AzureDatabaseName;Uid=$SQLUid;Pwd=$SQLPassword;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;" -DatabaseSecondaryConnectionString "Driver={ODBC Driver 13 for SQL Server};Server=tcp:$AzureSqlName,1433;Database=$AzureDatabaseName;Uid=$SQLUid;Pwd=$SQLPassword;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;" -ClientAccessName "$ConnectionBrokerLBDNSName.$DomainFQDN"
    }
    else {
        Write-Output "$BrokerServer.$DomainFQDN is already configured for High Availability"
    }
    Sleep 10
    #Check RD Broker Server
    $RDBrokerServercheck = Get-RDServer -ConnectionBroker "$BrokerServer.$DomainFQDN" -Role RDS-CONNECTION-BROKER
    if ($RDBrokerServercheck.Server -eq "$NewBrokerServer.$DomainFQDN" ) {
        Write-Output "RDS Broker Server '$NewBrokerServer.$DomainFQDN' is already part of the Deployment"        
    }
    else {        
        #Add RD Broker Server
        Write-Output "RD Broker Server '$NewBrokerServer.$DomainFQDN' is not part of the Deployment, Adding....."      
        Add-RDServer -Server "$NewBrokerServer.$DomainFQDN" -Role RDS-CONNECTION-BROKER -ConnectionBroker "$BrokerServer.$DomainFQDN" -Verbose
    }
}
Remove-PSSession $s3

###############
#End of Script#
###############
