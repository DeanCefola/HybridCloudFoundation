$vnet = Get-AzureRmVirtualNetwork -Name zzzz-Privatevnet -ResourceGroupName private
New-AzureRmDnsZone `
    -Name internet.local `
    -ResourceGroupName private `
    -ZoneType Private `
    -ResolutionVirtualNetworkId @($vnet.Id)


New-AzureRmDnsRecordSet `
    -Name dc01 -RecordType A `
    -ZoneName internet.local `
    -ResourceGroupName private `
    -Ttl 3600 `
    -DnsRecords (New-AzureRmDnsRecordConfig `
        -IPv4Address "192.168.100.4")
New-AzureRmDnsRecordSet `
    -Name dc02 -RecordType A `
    -ZoneName internet.local `
    -ResourceGroupName private `
    -Ttl 3600 `
    -DnsRecords (New-AzureRmDnsRecordConfig `
        -IPv4Address "192.168.100.5")

