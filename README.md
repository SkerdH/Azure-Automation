# Automated Onboarding with Azure: A Streamlined Approach

## Project Overview
This project is designed to create and implement a streamlined automation flow for handling onboarding requests within an Azure environment. By integrating multiple Azure components, this solution automates tasks, enhances efficiency, and ensures consistent resource management. The approach minimizes manual intervention while improving scalability and reliability across the infrastructure.

---

## Components and Configuration

### 1. Azure Storage Account
- **Purpose:** Centralizes secure storage for onboarding data.
- **Configuration:** Set up to store an Excel file with detailed onboarding requests, driving the automation process.

### 2. Azure Virtual Network (VNet)
- **Purpose:** Establishes a scalable and secure network infrastructure.
- **Configuration:** Created with well-defined subnets to support scalable deployment and enhanced security.

### 3. Network Security Group (NSG)
- **Purpose:** Enforces security policies across the network.
- **Configuration:** Applied to VNet subnets to maintain security rules and protect against unauthorized access.

### 4. Azure Automation Account
- **Purpose:** Centrally orchestrates tasks and workflows.
- **Configuration:** Used to automate both routine and complex workflows, reducing the need for manual intervention.

### 5. PowerShell Runbooks
- **Purpose:** Automates the execution of critical tasks.
- **Configuration:** Developed to automate tasks like VM deployment and network settings management.

### 6. Azure Log Analytics Workspace
- **Purpose:** Monitors and analyzes update compliance and system health.
- **Configuration:** Set up to collect data from various sources, integrated with Azure Sentinel for security management.

### 7. Update Management
- **Purpose:** Manages and automates VM updates comprehensively.
- **Configuration:** Configured within Azure Automation, connected to the Log Analytics workspace for automated update compliance monitoring.

### 8. Desired State Configuration (DSC)
- **Purpose:** Ensures consistent workload configurations across various environments, maintaining compliance and standardization.
- **DSC Setup Process:**
  - **Configuration File Creation:** Created a DSC file named `WebServer` using PowerShell, detailing the desired configurations for target machines.
  - **Compilation and Staging:** Compiled the configuration into a Managed Object Format (MOF) file and prepared it for deployment.
  - **Configuration Implementation:** Deployed the compiled configuration to target machines, ensuring they adhere to the defined standards.
  - **VM Registration:** Registered VMs with the DSC configuration to enable continuous management and enforcement of desired states.
  - **Automation and Alerts:** Set up automated reporting and alert systems within Log Analytics to monitor and respond to any deviations from the desired configuration.

---
<img src="https://i.imgur.com/omTY8ZJ.png" height="80%" width="80%" alt="LinkedInLearning"/>

## Automation Flow

### 1. Processing and Consolidating Onboarding Requests
- **ServiceNow Integration:** Handles incoming onboarding requests and tracks them for processing.
- **Consolidation of Requests:** Aggregates all requests into an Excel file, formatted to drive the subsequent automation processes.

### 2. Preparing the Automation Environment
- **Uploading to Azure Storage:** The consolidated Excel file is uploaded to Azure Storage, ready to trigger the automation workflow.
- **Azure Event Grid Activation:** Configured to capture the file upload event, ensuring real-time response to initiate the automation process.

### 3. VM Creation and Deployment Automation
- **Azure Automation Script Execution:**
  - **Authentication:** Uses `Connect-AzAccount` for secure access to Azure services under the correct subscription.
  - **Variable and Credential Retrieval:** Fetches essential details like the storage account key and SAS token.
  - **Excel File Handling:** Downloads and processes the Excel file from Azure Storage to extract VM deployment details.
  - **VM Deployment Initiator:** Executes the `Create-AzureVM.ps1` script for each entry in the Excel file, handling the VM setup.
  - **Cleanup Operations:** Deletes the downloaded Excel file to maintain a clean and secure environment.

### 4. Network Configuration and Management
- **Subnet Management:** Evaluates existing subnet capacity to accommodate new VMs and creates additional subnets if required.
- **VM Network Configuration:** Ensures each VM is configured with appropriate network settings, including public IP addresses and network interfaces.

### 5. Post-Deployment Automation and Change Management
- **Executing PowerShell Runbooks:** Utilizes PowerShell runbooks for final configurations and security policy applications across the deployed VMs.
- **Change Management Considerations:** Logs and reviews all changes, including VM deployment and network configurations, to ensure they meet organizational and security standards.

### 6. Update Management Configuration
- **Setup and Integration:** Integrated Update Management with Microsoft Log Analytics to provide comprehensive monitoring and analysis of update compliance across VMs.
- **Computer Group Definition:** Defined computer groups using dynamic membership rules or manual additions to categorize machines for more granular management.
- **Pre and Post-Scripts:** Configured scripts to execute before and after updates, ensuring compliance and addressing potential issues that may arise during the update process.
<img src="https://i.imgur.com/fMBj2fs.png" height="80%" width="80%" alt="LinkedInLearning"/>

### 7. Monitoring and Reporting
- **Automated Monitoring:** Leverages Azure Log Analytics and Update Management to continuously monitor the health and compliance of deployed VMs.
- **Reporting and Alerts:** Configures Azure Monitor and Azure Sentinel to generate alerts and reports based on specific metrics or events, facilitating proactive management and rapid response to potential issues.


```powershell
# Import required modules
Import-Module Az.Accounts
Import-Module Az.Storage
Import-Module ImportExcel

# Authenticate to Azure
Connect-AzAccount

# Set variables
$subscriptionId = "your-subscription-id"
$resourceGroupName = "your-resource-group-name"
$storageAccountName = "your-storage-account-name"
$containerName = "your-container-name"
$blobName = "vm-details.xlsx"

# Select the subscription
Select-AzSubscription -SubscriptionId $subscriptionId

# Get storage account key
$storageAccountKey = (Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -AccountName $storageAccountName)[0].Value

# Create storage context
$context = New-AzStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

# Generate SAS token
$sasToken = New-AzStorageContainerSASToken -Context $context -ContainerName $containerName -Permission "r" -ExpiryTime (Get-Date).AddHours(1)

# Construct the full blob URL with SAS token
$blobUrl = "https://$storageAccountName.blob.core.windows.net/$containerName/$blobName$sasToken"

# Download the Excel file
$excelFilePath = ".\vm-details.xlsx"
Invoke-WebRequest -Uri $blobUrl -OutFile $excelFilePath

# Read the Excel file
$vmDetails = Import-Excel -Path $excelFilePath

# Process each row in the Excel file
foreach ($vm in $vmDetails) {
    # Extract VM details
    $vmName = $vm.VMName
    $vmSize = $vm.VMSize
    $adminUsername = $vm.AdminUsername
    $adminPassword = $vm.AdminPassword | ConvertTo-SecureString -AsPlainText -Force

    # Call the VM creation script
    .\Create-AzureVM.ps1 -VMName $vmName -VMSize $vmSize -AdminUsername $adminUsername -AdminPassword $adminPassword
}

# Clean up: Remove the downloaded Excel file
Remove-Item -Path $excelFilePath -Force
VM Deployment and Subnet Management
```
## VM Deployment Script
This PowerShell script automates the deployment of Azure virtual machines (VMs) and manages network configuration by dynamically assigning subnets within a specified Virtual Network (VNet). It checks existing subnets for availability and creates new ones if necessary, ensuring that each VM is placed within a subnet with sufficient IP addresses. The script defines VM characteristics, including size, image, and admin credentials, and leverages Azure modules to handle VM creation and network setup seamlessly. Finally, the script can be integrated with Azure Log Analytics for monitoring, by configuring diagnostic settings on VMs and network components to send data to a Log Analytics workspace.
```powershell
# Import required modules
Import-Module Az.Compute
Import-Module Az.Network
Import-Module Az.Resources

# Authenticate to Azure (assuming already authenticated or using managed identity)

# Set variables
$subscriptionId = "your-subscription-id"
$resourceGroupName = "your-resource-group-name"
$location = "eastus"
$vnetName = "your-vnet-name"
$subnetPrefix = "Subnet"
$maxVMsPerSubnet = 250

# Select the subscription
Select-AzSubscription -SubscriptionId $subscriptionId

# Function to get or create a subnet
function Get-OrCreateSubnet {
    param (
        [string]$VNetName,
        [string]$SubnetPrefix,
        [int]$MaxVMsPerSubnet
    )

    $vnet = Get-AzVirtualNetwork -Name $VNetName -ResourceGroupName $resourceGroupName
    $subnets = $vnet.Subnets

    foreach ($subnet in $subnets) {
        $usedIPs = (Get-AzNetworkInterface | Where-Object { $_.IpConfigurations.Subnet.Id -eq $subnet.Id }).Count
        if ($usedIPs -lt $MaxVMsPerSubnet) {
            return $subnet
        }
    }

    # If all subnets are full, create a new one
    $newSubnetNumber = $subnets.Count + 1
    $newSubnetName = "${SubnetPrefix}${newSubnetNumber}"
    $newSubnetAddressPrefix = "10.0.${newSubnetNumber}.0/24"

    $vnet = Add-AzVirtualNetworkSubnetConfig -Name $newSubnetName -AddressPrefix $newSubnetAddressPrefix -VirtualNetwork $vnet
    $vnet | Set-AzVirtualNetwork

    return Get-AzVirtualNetworkSubnetConfig -Name $newSubnetName -VirtualNetwork $vnet
}

# Function to deploy a VM
function Deploy-AzureVM {
    param (
        [string]$VMName,
        [string]$VMSize,
        [string]$SubnetId,
        [string]$AdminUsername,
        [SecureString]$AdminPassword
    )

    # Create a public IP address
    $publicIp = New-AzPublicIpAddress -Name "${VMName}-pip" -ResourceGroupName $resourceGroupName -Location $location -AllocationMethod Dynamic

    # Create a network interface
    $nic = New-AzNetworkInterface -Name "${VMName}-nic" -ResourceGroupName $resourceGroupName -Location $location -SubnetId $SubnetId -PublicIpAddressId $publicIp.Id

    # Define the VM configuration
    $vmConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize

    # Set the VM operating system
    $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Windows -ComputerName $VMName -Credential (New-Object PSCredential ($AdminUsername, $AdminPassword))

    # Add the network interface to the VM
    $vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id

    # Specify the image for the VM
    $vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2019-Datacenter" -Version "latest"

    # Create the VM
    New-AzVM -ResourceGroupName $resourceGroupName -Location $location -VM $vmConfig
}

# Main script execution

# Get or create a subnet
$subnet = Get-OrCreateSubnet -VNetName $vnetName -SubnetPrefix $subnetPrefix -MaxVMsPerSubnet $maxVMsPerSubnet

# VM deployment parameters (in a real scenario, these could come from a file or user input)
$vmParams = @{
    VMName = "TestVM001"
    VMSize = "Standard_B2s"
    AdminUsername = "azureuser"
    AdminPassword = (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force)
}

# Deploy the VM
Deploy-AzureVM -VMName $vmParams.VMName -VMSize $vmParams.VMSize -SubnetId $subnet.Id -AdminUsername $vmParams.AdminUsername -AdminPassword $vmParams.AdminPassword

Write-Host "VM deployment completed successfully."
Integration with Log Analytics
```

## DSC
This PowerShell Desired State Configuration (DSC) script is designed to automate the deployment and configuration of a web server on a specified node using Azure resources. It installs necessary Windows features such as IIS, ASP.NET 4.5, and IIS management tools, ensuring these components are present and functional. The script also sets up and starts the default IIS website, with its files located in the standard directory, and it handles dependencies to ensure operations execute in the correct order. Additionally, it securely copies an index.htm file from an Azure File Share to the web server's root directory, utilizing provided Azure storage credentials for authenticated access.
```powershell
# Defines a DSC configuration named WebServerConfig.
Configuration WebServerConfig
{
    # Parameters required for the script to run, must be supplied by the user.
    param
    (
        [Parameter(Mandatory=$true)]
        [String]$NodeName,  # The name of the target node where the configuration will be applied.

        [Parameter(Mandatory=$true)]
        [PSCredential]$AzureStorageCredential,  # Credential object for accessing Azure Storage.

        [Parameter(Mandatory=$true)]
        [String]$AzureFileShareName,  # Name of the Azure File Share from which files will be copied.

        [Parameter(Mandatory=$true)]
        [String]$AzureStorageAccountName  # Name of the Azure Storage Account.
    )

    # Importing necessary DSC resources from specified modules.
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xWebAdministration

    # Defines the configuration for a specific node.
    Node $NodeName
    {
        # Ensures that the IIS role is installed on the node.
        WindowsFeature IIS
        {
            Ensure = "Present"  # The state of the feature; here it ensures IIS is installed.
            Name = "Web-Server"  # The name of the feature to install.
        }

        # Ensures that ASP.NET 4.5 is installed, enabling ASP.NET applications.
        WindowsFeature ASP
        {
            Ensure = "Present"
            Name = "Web-Asp-Net45"
        }

        # Ensures the IIS Management Console is installed, providing a GUI for managing IIS.
        WindowsFeature WebServerManagementConsole
        {
            Ensure = "Present"
            Name = "Web-Mgmt-Console"
        }

        # Installs scripting tools necessary for IIS management scripting.
        WindowsFeature WebScriptingTools
        {
            Ensure = "Present"
            Name = "Web-Scripting-Tools"
        }

        # Ensures that the default website is configured and running on IIS.
        xWebsite DefaultSite 
        {
            Ensure = "Present"
            Name = "Default Web Site"  # The name of the website to ensure presence.
            State = "Started"  # The desired state of the website, ensuring it is running.
            PhysicalPath = "C:\\inetpub\\wwwroot"  # Where the website files are stored.
            DependsOn = "[WindowsFeature]IIS"  # Only configures the website after IIS is installed.
        }

        # Copies the index.htm file from an Azure File Share to the website’s root directory.
        File IndexFile
        {
            Ensure = "Present"
            Type = "File"
            SourcePath = "\\\\${AzureStorageAccountName}.file.core.windows.net\\${AzureFileShareName}\\index.htm"  # Network path to the file.
            DestinationPath = "C:\\inetpub\\wwwroot\\index.htm"  # Local path where the file will be stored.
            Credential = $AzureStorageCredential  # Credentials used for accessing the file share.
            DependsOn = "[xWebsite]DefaultSite"  # Ensures the website is ready before copying the file.
        }
    }
}

```

