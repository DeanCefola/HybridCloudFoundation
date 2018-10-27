
Function Enable-AzureRMVMEncryption {
<# 
 .Synopsis
    Enable Azure Disk Encryption on Azure VMs with KeyVault Secrets

 .Description
    Enable Azure VM Disk Encryption Service
     
 .Parameter Prefix
    This code for will be used as a prefix for all resources deployed to keep them unique

 .Parameter Application
    name of the application workload for this deployment     

 .Example
 # Enable Azure Disk Encryption for your Application VMs
Enable-AzureRMVMEncryption `
    -Prefix j99 `
    -Application sap

#>
[Cmdletbinding()]
Param (
    [Parameter(Mandatory=$true)]
        [string]$Prefix,
    [Parameter(Mandatory=$true)]
        [string]$Application 
)

Begin {    
    $RGName = $Prefix+"-RG-$Application"
    $KVName = $Prefix+"KeyVault"
    $KVRGName = $Prefix+"-RG-Security"
    $AADDisplayName = $Prefix+"AzureDiskEncryptApp"
    $AADClientSecret = $Prefix+"disksecret"
    $AAD_ID = (Get-AzureRmADApplication -DisplayNameStartWith $AADDisplayName).ApplicationId.Guid
    $AAD_SPN = (Get-AzureRmADServicePrincipal -SearchString $AADDisplayName).Id.Guid
    $KV = Get-AzureRmKeyVault -VaultName $KVName -ResourceGroupName $KVRGName
    $KVuri = $KV.VaultUri
    $KVrid = $kv.ResourceId
    $VMName = Get-AzureRmVM -ResourceGroupName $RGName | Where-Object -Property name -NotMatch 'NVA'
}

Process {       
    #####################################################
    #                   Encrypt Disk                    #
    #####################################################
    Foreach ($VM in $VMName) {
        Write-Host `
            -ForegroundColor Cyan `
            -BackgroundColor Black `
            "Begin Disk Encryption for VM -" $VM.name
        Set-AzureRmVMDiskEncryptionExtension `
            -ResourceGroupName $RGName `
            -VMName $VM.Name `
            -AadClientID $AAD_ID `
            -AadClientSecret $AADClientSecret `
            -DiskEncryptionKeyVaultUrl $KVuri `
            -DiskEncryptionKeyVaultId $KVrid `
            -VolumeType All `
            -Force `
            -Verbose
    }

}

End {
    Write "Script Complete"
}

}

<#
Enable-AzureRMVMEncryption -Prefix j99 -Application sap
#>
