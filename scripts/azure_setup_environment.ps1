
Function New-AzureRMHCFDeployment {
<# 
 .Synopsis
    Hybrid Cloud Foundation setup Function will deploy 6 Azure Resource Groups
    This will setup the core infrastructue for HCF including:
    -RG-Identity
        1.  2 Domain Controllers (HA)
    -RG-SharedServices
        2.  2 DFS Servers (HA)
        3.  Remote Desktop Services Farm
            a.  2 Connection Brokers (HA)
                i.  1 Azure SQL Server Instance 
                ii.  1 Azure SQL database
            b.  2 Web Access Servers (HA)
            c.  4 Session Host Servers (HA)
            d.  1 License server     
    -RG-security
        1.  Azure Storage Account
            a.  Monitoring account
            b.  NVA storage accounts
            c.  Azure KeyVault
                i.  Secrets
                    1.  Local admin password
                    2.  Azure SQL Admin Password
            d.  Azure Backup Recovery Services Vault
    -RG-vnets
        1.  2 Virtual Networks (1 for core, 1 for application)
            a.  Peerings between virtual networks
            b.  12 Subnets
            c.  Service Endpoints for Azure Storage enabled
        2.  1 Network Security Group per subnet 
        3.  3 User Defined Route Tables
    -RG-DisasterRecovery (DR Region)
        1.  Azure Site Recovery Recovery Service Vault (DR Region)
    -RG-[(<Application>)]
        1.  Application workload

 .Description
    Hybrid Cloud Foundation Offering Setup Function
     
 .Parameter Prefix
    This code for will be used as a prefix for all resources deployed to keep them unique

 .Parameter Application
    name of the application workload for this deployment 

 .Parameter SourcePath
    root path to the templates and scripts, do not use a trailing '\'

 .Parameter Location
    primary Azure region used in this deployment 

 .Parameter DR_Location
    DR Region used in this deployment  

 .Parameter KeyVaultAdmin
    Email address that will administer KeyVault secrets 

 .Parameter LocalLocalAdminUser
    Local Admin account for the servers, cannot be root, admin or administrator

 .Parameter LocalAdminPassword
    Local Admin Password, this password will be registered as a KeyVault Secret
    
 .Parameter SQLAdminUser
    SQL Admin account for Azure SQL, or SQL Server

 .Parameter SQLAdminPassword
    SQL Admin Password, this password will be registered as a KeyVault Secret
    

 .Example
 # Create new Azure Deployment
New-AzureRMDeployment `
    -Prefix j99 `
    -Application sap `
    -SourcePath C:\temp\Azure\Deployment `
    -Location eastus2 `
    -DR_Location westus2 `
    -KeyVaultAdmin keyvultadmin@company.com `
    -LocalAdminUser localadmin `
    -LocalAdminPassword P@$$w0rd123! `
    -SQLAdminUser sqladmin `
    -SQLAdminPassword $3cureP@s$w0rd312!

#>
[Cmdletbinding()]
Param (
    [Parameter(Mandatory=$true)]
        [string]$Prefix,
    [Parameter(Mandatory=$true)]
        [string]$Application,
    [Parameter(Mandatory=$true)]
        [string]$SourcePath='C:\_VSTS\MSDEAN\HCF\HCF',    
    [Parameter(Mandatory=$true)]
        [validateset('australiaeast','australiasoutheast','brazilsouth','canadacentral', `
        'canadaeast','centralindia','centralus','eastasia','eastus','eastus2','japaneast', `
        'japanwest','koreacentral','koreasouth','northcentralus','northeurope','southcentralus', `
        'southeastasia','southindia','uksouth','ukwest','westcentralus','westeurope','westindia', `
        'westus','westus2')]
        [string]$Location,
    [Parameter(Mandatory=$true)]
        [validateset('australiaeast','australiasoutheast','brazilsouth','canadacentral', `
        'canadaeast','centralindia','centralus','eastasia','eastus','eastus2','japaneast', `
        'japanwest','koreacentral','koreasouth','northcentralus','northeurope','southcentralus', `
        'southeastasia','southindia','uksouth','ukwest','westcentralus','westeurope','westindia', `
        'westus','westus2')]
        [string]$DR_Location,
    [Parameter(Mandatory=$true)]
        [string]$KeyVaultAdmin,
    [Parameter(Mandatory=$true)]        
        [string]$LocalAdminUser,    
    [Parameter(Mandatory=$true)]        
        [Security.SecureString]$LocalAdminPassword,
    [Parameter(Mandatory=$true)]        
        $SQLAdminUser,
    [Parameter(Mandatory=$true)]        
        [Security.SecureString]$SQLAdminPassword
)

Begin {    
    cls
    $Prefix = $Prefix.ToLower()
    $RGName = $Prefix+"-RG-$Application"
    $KVName = $Prefix+"KeyVault"
    $STName = $Prefix+"staging01"
    $STName = $STName.ToLower()
    $SecretName = "Built-Local-Admin-Passsword"
    $SQLSecretName = "SQL-Admin-Passsword"
    $AADDisplayName = $Prefix+"AzureDiskEncryptApp"
    $AADClientSecret = $Prefix+"disksecret"
    $DSCPath = "$SourcePath\dsc\"
    $ScriptsPath = "$SourcePath\scripts\"
}

Process {   
    #####################################################
    #             Create Resource Groups                #
    #####################################################
    $RGArray = @(
      #  ,@("-RG-$Application"; $Location)
      #  ,@("-RG-identity"; $Location)
        ,@("-RG-security"; $Location)
      #  ,@("-RG-sharedservices"; $Location)
      #  ,@("-RG-vnets"; $Location)
      #  ,@("-RG-DisasterRecovery"; $DR_Location)
    )
    foreach($RG in $RGArray) {
        $RG_Name = $Prefix + $RG[0]
        $RG_Location = $RG[1]
        if ((Get-AzureRmResourceGroup -Name $RG_Name -ErrorAction SilentlyContinue) -eq $null) {
            Write-Host `
                -ForegroundColor Green `
                -BackgroundColor Black `
                "Creating New Azure Resource Group $RG_Name"
            ""
            New-AzureRmResourceGroup `
                -Name $RG_Name `
                -Location $RG_Location
            wait-event -Timeout 5
    }        
        Else {
            Write-Host `
                -ForegroundColor Yellow `
                -BackgroundColor Black `
                "ResourceGroup $RG_Name already exists"
            ""
            wait-event -Timeout 5
        }  
    }
    $RGSecurity = $Prefix+"-RG-security" 
    #####################################################
    #              Create Azure Key Vault               #
    #####################################################    
    if((Get-AzureRmKeyVault -ResourceGroupName $RGSecurity -VaultName $KVName -ErrorAction SilentlyContinue) -eq $null) {
    Write-Host `
        -ForegroundColor Green `
        -BackgroundColor Black `
        "Creating New Azure KeyVault"
    ""
    New-AzureRmKeyVault `
        -VaultName $KVName `
        -ResourceGroupName $RGSecurity `
        -Location $Location `
        -EnabledForDeployment `
        -EnabledForTemplateDeployment `
        -EnabledForDiskEncryption `
        -Sku Premium `
        -DefaultProfile (Get-AzureRmContext)
    wait-event -timeout 5
    ''
    Write-Host `
        -ForegroundColor green `
        -BackgroundColor Black `
        "Setting VaultAdmin permissions"
    ""
    $ID = (Get-AzureRmADUser -UserPrincipalName $KeyVaultAdmin).id.guid
    Set-AzureRmKeyVaultAccessPolicy `
        -VaultName $KVName  `
        -ResourceGroupName $RGSecurity `
        -ObjectId $ID `
        -PermissionsToSecrets get, list, set, delete, backup, restore, recover, purge `
        -Verbose
    }
    Else {
        Write-Host `
            -ForegroundColor Yellow `
            -BackgroundColor Black `
            "KeyVault already exists"
        ""
            Write-Host `
            -ForegroundColor green `
            -BackgroundColor Black `
            "Setting VaultAdmin permissions"
        ""
        $ID = (Get-AzureRmADUser -UserPrincipalName $KeyVaultAdmin).id.guid
        Set-AzureRmKeyVaultAccessPolicy `
            -VaultName $KVName  `
            -ResourceGroupName $RGSecurity `
            -ObjectId $ID `
            -PermissionsToSecrets get, list, set, delete, backup, restore, recover, purge `
            -Verbose
        ''
        wait-event -timeout 5
    }
    #####################################################
    #           Create Azure Key Vault Secrets          #
    #####################################################
    if ((Get-AzureKeyVaultSecret -VaultName $KVName -Name $SecretName -ErrorAction SilentlyContinue) -eq $null) {
        Write-Host `
            -ForegroundColor Green `
            -BackgroundColor Black `
            "Creating New Local Admin Secret"
        ""
        Set-AzureKeyVaultSecret `
            -VaultName $KVName `
            -Name $secretName `
            -SecretValue $LocalAdminPassword    
        }
    Else {
        Write-Host `
            -ForegroundColor Yellow `
            -BackgroundColor Black `
            "Local Admin Secret already exists"
        ""
    }
    if ((Get-AzureKeyVaultSecret -VaultName $KVName -Name $SQLSecretName -ErrorAction SilentlyContinue) -eq $null) {
        Write-Host `
            -ForegroundColor Green `
            -BackgroundColor Black `
            "Creating New SQL Secret"
        ""
        Set-AzureKeyVaultSecret `
            -VaultName $KVName `
            -Name $SQLsecretName `
            -SecretValue $SQLAdminPassword 
        }
    Else {
        Write-Host `
            -ForegroundColor Yellow `
            -BackgroundColor Black `
            "SQL Secret already exists"
        ""
    }
    #####################################################
    #    Create Azure AD Application for Encryption     #
    #####################################################    
    If ((Get-AzureRmADApplication -DisplayNameStartWith $AADDisplayName -ErrorAction SilentlyContinue) -eq $null) {
        Write-Host `
            -ForegroundColor Green `
            -BackgroundColor Black `
            "Creating Disk Encryption Application"
        ""
        $AADSecret = ConvertTo-SecureString `
        -String $AADClientSecret `
        -AsPlainText `
        -Force
        $AAD_App = New-AzureRmADApplication `
            -DisplayName $AADDisplayName `
            -HomePage "http://homepage$AADDisplayName" `
            -IdentifierUris "http://$AADDisplayName" `
            -Password $AADSecret            
        $AAD_ID = $AAD_App.ApplicationId.Guid
        ""
        New-AzureRmADServicePrincipal -ApplicationId $AAD_ID
        ""
        $AAD_SPN = (Get-AzureRmADServicePrincipal -SearchString $AADDisplayName).Id.Guid
        Set-AzureRmKeyVaultAccessPolicy `
            -VaultName $KVName  `
            -ResourceGroupName $RGSecurity `
            -ServicePrincipalName $AAD_ID  `
            -PermissionsToKeys wrapKey  `
            -PermissionsToSecrets set 
    }
    Else {
        Write-Host `
            -ForegroundColor Yellow `
            -BackgroundColor Black `
            "Application already exists"
        ""      
        $AAD_ID = (Get-AzureRmADApplication -DisplayNameStartWith $AADDisplayName).ApplicationId.Guid
        $AAD_SPN = (Get-AzureRmADServicePrincipal -SearchString $AADDisplayName).Id.Guid
        Set-AzureRmKeyVaultAccessPolicy `
            -VaultName $KVName  `
            -ResourceGroupName $RGSecurity `
            -ServicePrincipalName $AAD_ID  `
            -PermissionsToKeys wrapKey `
            -PermissionsToSecrets set
    }
    <#####################################################
    #              Create Storage Account               #
    #####################################################
    if ((Get-AzureRmStorageAccount -ResourceGroupName ($Prefix+"-RG-security") -Name $STName -ErrorAction SilentlyContinue) -eq $null) {
        Write-Host `
            -ForegroundColor Green `
            -BackgroundColor Black `
            "Creating New Storage Account for Artifacts"
        ""
        New-AzureRmStorageAccount `
            -ResourceGroupName ($Prefix+"-RG-security") `
            -Name $STName `
            -SkuName Standard_LRS `
            -Location $Location `
            -Kind StorageV2 `
            -AccessTier Cool
        $stokey = (Get-AzureRmStorageAccountKey -ResourceGroupName ($Prefix+"-RG-security") -Name $STName).Value[0]    
        $StorageContext = New-AzureStorageContext `
            -StorageAccountName $STName `
            -StorageAccountKey $stokey  
    }    
    Else {
        Write-Host `
            -ForegroundColor Yellow `
            -BackgroundColor Black `
            "Artifact Storage Account already exists"
        ""    
        $stokey = (Get-AzureRmStorageAccountKey -ResourceGroupName ($Prefix+"-RG-security") -Name $STName).Value[0]    
        $StorageContext = New-AzureStorageContext `
            -StorageAccountName $STName `
            -StorageAccountKey $stokey
    }
    #####################################################
    #              Create Storage Containers            #
    #####################################################
    if ((Get-AzureStorageContainer -Name 'dsc' -Context $StorageContext -ErrorAction SilentlyContinue) -eq $null) {
        Write-Host `
            -ForegroundColor Green `
            -BackgroundColor Black `
            "Creating Container for DSC Artifacts"
        ""
        Wait-Event -Timeout 5    
        New-AzureStorageContainer `
            -Context $StorageContext `
            -Name 'dsc' `
            -Permission Container
    }
    Else {
        Write-Host `
            -ForegroundColor Yellow `
            -BackgroundColor Black `
            "DSC Container already exists"
        ""    
    }
    if ((Get-AzureStorageContainer -Name 'scripts' -Context $StorageContext -ErrorAction SilentlyContinue) -eq $null) {
        Write-Host `
            -ForegroundColor Green `
            -BackgroundColor Black `
            "Creating Container for Scripts"
        ""
        Wait-Event -Timeout 5    
        New-AzureStorageContainer `
            -Context $StorageContext `
            -Name 'scripts' `
            -Permission Container    
    }
    Else {
        Write-Host `
            -ForegroundColor Yellow `
            -BackgroundColor Black `
            "Templates Container already exists"
        ""  
    }
    #####################################################
    #              Upload files to Storage              #  
    #####################################################
    $Scripts_Files = (Get-ChildItem -Path $ScriptsPath).Name   
    $DSC_Files = (Get-ChildItem -Path $DSCPath).Name   
    foreach ($Scripts in $Scripts_Files) {
        $ConfigPath = "$ScriptsPath$Scripts"
        Set-AzureStorageBlobContent `
            -Blob $Scripts `
            -Container 'scripts' `
            -File $ConfigPath `
            -Context $StorageContext `
            -Force
    }
    foreach ($DSC in $DSC_Files) {
        $ConfigPath = "$DSCPath$dsc"
        Publish-AzureRmVMDscConfiguration `
            -ResourceGroupName ($Prefix+"-RG-security") `
            -StorageAccountName $STName `
            -ContainerName 'dsc' `
            -ConfigurationPath  $ConfigPath `
            -Force
    }

    #>
}

End {
    Clear-History
}

}

####################################################
#               New Azure Deployment               #
####################################################
New-AzureRMHCFDeployment `
       -Prefix zx9 `
       -SourcePath 'C:\_VSTS\MSDEAN\HCF\HCF' `
       -Application sap `
       -Location eastus2 `
       -DR_Location westus2 `
       -KeyVaultAdmin deacef@microsoft.com `
       -LocalAdminUser localadmin `
       -SQLAdminUser sqladmin

