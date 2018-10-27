**Overview for Azure Hybrid Cloud Foundation Templates:**
============================

**This Master template creates the following resources:**
============================
	-2 Virtual Network
	-1 monitoring storage account
	-1 storage account for NVA
	-2 NVAs in HA mode 
	-2 Active Directory Domain Controllers
	-2 DFS servers in HA
	-RDSFarm
		-2 RDS Connection Brokers
		-1 Azure SQL server instance 
			-1 Azure SQL Database
		-2 RDS Web Access Servers
		-4 RDS Session Hosts
	-Application
		-After the HCF is in place install your application on the spoke virtual network
		-If more appication space is needed either add address spaces to the spoke vnet or create a new vnet spoke and peer to hub

**Deployment Parameters:**
============================
	-Client_Prefix:  This is a unique identifier that will be used as a prefix for resources that need globally unique IDs.  
	-IPRange: you are free to specify any IP range you like, just specify the first 2 octets (ex. 10.0 or 172.18)   
	-TAGS: 
		-Application - Name of application (SAP, Sharepoint, CommVault, Etc...)
		-Costcenter  - Cost center for chargeback/showback
		-Department  - Name of Department who owns these resources
		-Environment - Options are Dev / Tst / qa / prd
	-Location: - currently the allowed locations are limited to US regions, but you can update to include/exclude regions are you need
	-Security:
		-Admin_UserName: - local admin username 
		-Admin_Password: - local admin password
		-Auth_sshPublicKey: NVA related parameter, string field for SSH key
		-Auth_authenticationType: - NVA related parameter, options are ssh or password
		-Domain:  - NetBios domain names only

**Virtual Network:**
============================
	-HUB
		-Single Address Space
		-Multiple subnets
			-Management - Identity and security stack 
			-NVAManagement - NVA management interfaces
			-NVADiags - NVA diagnostics (not all NVAs require this interface)
			-NVAUntrusted - external interfaces, or internet facing
			-NVATrusted - Internal interfaces
	-SPOKE
		-Single Address Space
		-Multiple subnets
			-Web - for web tier servers or internal Azure load balancers
			-App - for application tier servers, or SAP Central Instances
			-Database - for Database tier servers
			-Tools - Allocated to Application Gateways, if required 

**Network Security Group:**
============================
	-Each Subnet will have 1 NSG applied 
	-VMs generally do not have a NSG generally applied directly

**VM General Details:**
============================
	-Each VM in the deployment will have 1 NIC 
	-VMs will have at least 1 data disk 	

**Active Directory Domain:**
============================
	-Deploy 2 domain controllers 
	-FSMO roles are deployed to the first DC
	-ADDS is deployed with PowerShell DSC

**Distributed File Services:**
============================
	-Deploy 2 DFS Servers in the same namespace 
	-DFS is used as the location for User disks in RDS
	-DFS is deployed with PowerShell scripts

**RDSFarm:**
============================
	-Multiple RDS roles
		-2 Connection Brokers in HA using Azure SQL
		-2 Web Access Servers in HA
		-4 Session Host Servers 
	-RDS is deployed with PowerShell DSC and scripts
	-User disks are stored on the DFS Servers
