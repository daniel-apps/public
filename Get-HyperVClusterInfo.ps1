############################################################################################################
# This script was written by Daniel Apps (Yes, ChatGPT did the heavy lifting :D )
# Author: Daniel Apps
# Date: 4/4/2024
# Version: 2.1
############################################################################################################


# Logging function to improve visibility with log levels
function Write-Log
{
    param (
        [string]$message,
        [string]$level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "$timestamp [$level] - $message"
}

# Function to close CIM session safely
function Close-CimSessionSafely
{
    param (
        [CimSession]$cimSession
    )
    if ($null -ne $cimSession)
    {
        try
        {
            $cimSession | Remove-CimSession
            Write-Log "CIM session closed successfully" "INFO"
        }
        catch
        {
            Write-Log "Failed to close CIM session: $_" "ERROR"
        }
    }
}

function Get-S2DData
{
    param (
        [CimSession]$cimSession
    )

    $s2dData = @{
        VirtualDisks  = @()
        PhysicalDisks = @()
    }

    try
    {
        # Retrieve virtual disk information from the correct namespace
        $virtualDisks = Get-CimInstance -CimSession $cimSession -Namespace "root/microsoft/windows/storage" -ClassName MSFT_VirtualDisk
        foreach ($vDisk in $virtualDisks)
        {
            $volume = Get-Volume -CimSession $cimSession | Where-Object FileSystemLabel -eq $vDisk.FriendlyName
            $s2dData.VirtualDisks += [pscustomobject]@{
                FriendlyName       = $vDisk.FriendlyName
                ResiliencySetting  = $vDisk.ResiliencySettingName
                NumberOfDataCopies = $vDisk.NumberOfDataCopies
                Deduplication      = $vDisk.IsDeduplicationEnabled
                UsedPercentage     = ($vDisk.Size - $volume.SizeRemaining) / $vDisk.Size
                UsedCapacity       = if (($vDisk.Size - $volume.SizeRemaining) -ge 1TB) { "{0:N2} TB" -f (($vDisk.Size - $volume.SizeRemaining) / 1TB) } else { "{0:N2} GB" -f (($vDisk.Size - $volume.SizeRemaining) / 1GB) }
                Remaining          = if ($volume.SizeRemaining -ge 1TB) { "{0:N2} TB" -f ($volume.SizeRemaining / 1TB) } else { "{0:N2} GB" -f ($volume.SizeRemaining / 1GB) }
                TotalSize          = if ($vDisk.Size -ge 1TB) { "{0:N2} TB" -f ($vDisk.Size / 1TB) } else { "{0:N2} GB" -f ($vDisk.Size / 1GB) }
                FootprintOnPool    = if ($vDisk.FootprintOnPool -ge 1TB) { "{0:N2} TB" -f ($vDisk.FootprintOnPool / 1TB) } else { "{0:N2} GB" -f ($vDisk.FootprintOnPool / 1GB) }
                OperationalStatus  = $vDisk.OperationalStatus
                HealthStatus       = $vDisk.HealthStatus
            }
        }

        # Retrieve physical disk information from the correct namespace
        $physicalDisks = Get-CimInstance -CimSession $cimSession -Namespace "root/microsoft/windows/storage" -ClassName MSFT_PhysicalDisk | Where-Object DeviceID -ne 0
        foreach ($pDisk in $physicalDisks)
        {
            $s2dData.PhysicalDisks += [pscustomobject]@{
                FriendlyName      = $pDisk.FriendlyName
                SerialNumber      = $pDisk.SerialNumber
                MediaType         = $pDisk.MediaType
                CanPool           = $pDisk.CanPool
                OperationalStatus = $pDisk.OperationalStatus
                HealthStatus      = $pDisk.HealthStatus
                Usage             = $pDisk.Usage
                UsedCapacity      = $pDisk.AllocatedSize
                Size              = if ($pDisk.Size -ge 1TB) { "{0:N2} TB" -f ($pDisk.Size / 1TB) } else { "{0:N2} GB" -f ($pDisk.Size / 1GB) }
            }
        }

        Write-Log "Retrieved S2D data successfully"
    }
    catch
    {
        Write-Log "Failed to retrieve S2D data: $_" "ERROR"
    }

    return $s2dData
}


# Initialize an empty array to store cluster details
$clustersArray = @()

# Retrieve domain name
try
{
    $domain = (Get-WmiObject win32_computersystem).Domain
    Write-Log "Domain retrieved: $domain"
}
catch
{
    Write-Log "Failed to retrieve domain: $_" "ERROR"
    exit 1
}

# Retrieve clusters in the domain
try
{
    $clusters = Get-Cluster -Domain $domain -Name 999phcic001p010
    Write-Log "Clusters found: $($clusters.Count)"
}
catch
{
    Write-Log "Failed to retrieve clusters: $_" "ERROR"
    exit 1
}

# Loop through each cluster and populate its details
foreach ($cluster in $clusters)
{
    Write-Log "Processing cluster: $($cluster.Name)"

    # Check if S2D is enabled for the cluster
    $s2dEnabled = $cluster.S2DEnabled -eq 1  # 1 means enabled
    Write-Log "S2D Enabled: $s2dEnabled for cluster: $($cluster.Name)"

    # Retrieve BlockCacheSize if S2D is enabled, otherwise set to "N/A"
    $blockCacheSize = if ($s2dEnabled) { $cluster.BlockCacheSize } else { "N/A" }
    Write-Log "BlockCacheSize: $blockCacheSize"

    try
    {
        Write-Log "Starting CIM session for S2D data on cluster: $($cluster.Name)"
        $cimSession = New-CimSession -ComputerName $cluster.Name

        # Retrieve S2D data
        $s2dData = Get-S2DData -cimSession $cimSession

        # Populate virtual and physical disks
        $virtualDisks = $s2dData.VirtualDisks | Sort-Object FriendlyName
        $physicalDisks = $s2dData.PhysicalDisks | Sort-Object MediaType, FriendlyName  

    }
    catch
    {
        Write-Log "Failed to start CIM session: $_" "ERROR"
    }
    finally
    {
        Close-CimSessionSafely -cimSession $cimSession
    }

    # Initialize a cluster object
    $clusterInfo = [pscustomobject]@{
        Name           = $cluster.Name
        Version        = $cluster.Version
        S2DEnabled     = $s2dEnabled
        BlockCacheSize = $blockCacheSize
        VirtualDisks   = $virtualDisks
        PhysicalDisks  = $physicalDisks
        Nodes          = @()
    }

    # Retrieve nodes in the cluster
    try
    {
        $nodes = Get-ClusterNode -Cluster $cluster.Name
        Write-Log "Found $($nodes.Count) nodes for cluster $($cluster.Name)"
    }
    catch
    {
        Write-Log "Failed to retrieve nodes for cluster $($cluster.Name): $_"
        continue  # Skip to the next cluster if nodes cannot be retrieved
    }

    # Loop through each node to gather information
    foreach ($node in $nodes)
    {
        try
        {
            Write-Log "Gathering information for node: $($node.Name)"
			
            # Retrieve node state explicitly
            $nodeDetails = Get-ClusterNode -Name $node.Name -Cluster $cluster.Name
            $nodeState = [string]$nodeDetails.State
			
            # Retrieve QoS settings at node level using Invoke-Command
            Write-Log "Retrieving QoS Traffic Class settings for node: $($node.Name)"
            $qosTrafficClasses = Invoke-Command -ComputerName $node.Name -ScriptBlock {
                Get-NetQosTrafficClass | Select-Object Name, Algorithm, Bandwidth, Priority
            }

            Write-Log "Retrieving QoS Policies for node: $($node.Name)"
            $qosPolicies = Invoke-Command -ComputerName $node.Name -ScriptBlock {
                Get-NetQosPolicy | Select-Object Name, Template, NetDirectPort, PriorityValue
            }

            Write-Log "Retrieving QoS Flow Control settings for node: $($node.Name)"
            $qosFlowControls = Invoke-Command -ComputerName $node.Name -ScriptBlock {
                Get-NetQosFlowControl | Select-Object Priority, Enabled
            }

            # Gather node-level QoS settings
            $nodeQosSettings = [pscustomobject]@{
                TrafficClasses = $qosTrafficClasses
                Policies       = $qosPolicies
                FlowControl    = $qosFlowControls
            }

            # Retrieve CPU, memory, and network information
            Write-Log "Retrieving CPU and memory info for node: $($node.Name)"
            $processors = Get-WmiObject -Class Win32_Processor -ComputerName $node.Name
            $socketCount = $processors.Count
            $physicalCores = ($processors | Measure-Object -Property NumberOfCores -Sum).Sum
            $logicalCores = ($processors | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
            $hyperThreading = if ($logicalCores -gt $physicalCores) { "Enabled" } else { "Disabled" }
            $physicalMemory = (Get-WmiObject -Class Win32_ComputerSystem -ComputerName $node.Name).TotalPhysicalMemory / 1MB
            $availableMemory = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $node.Name).FreePhysicalMemory / 1MB
            $osVersion = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $node.Name).Version

            # Retrieve all adapter configurations and QoS settings
            Write-Log "Retrieving network adapter details for node: $($node.Name)"
            Write-Log "Retrieving network adapter details for node: $($node.Name)"
            $allAdapterConfigs = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $node.Name
            $allDrivers = Get-WmiObject -Class Win32_PnPSignedDriver -ComputerName $node.Name
            $adapterResults = Get-WmiObject -Class Win32_NetworkAdapter -ComputerName $node.Name | Where-Object { $_.NetConnectionStatus -ne $null } | Sort-Object Name

            Write-Log "Retrieving virtual switch info for node: $($node.Name)"
            $virtualSwitches = Get-VMSwitch -ComputerName $node.Name

            # Initialize network adapters array explicitly
            $networkAdapters = @() # Start as an empty array

            foreach ($adapter in $adapterResults)
            {
                $connectedSwitch = $null

                # Check if the adapter is part of a virtual switch
                foreach ($vSwitch in $virtualSwitches)
                {
                    $vSwitchAdapters = Get-VMSwitchTeam -Name $vSwitch.Name -ComputerName $node.Name | Select-Object -ExpandProperty NetAdapterInterfaceDescription
                    if ($vSwitchAdapters -contains $adapter.Name)
                    {
                        $connectedSwitch = $vSwitch.Name
                        break
                    }
                }

                # Match adapter configuration for IP
                $adapterConfig = $allAdapterConfigs | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
                $ipAddress = if ($adapterConfig.IPAddress) { $adapterConfig.IPAddress[0] } else { "N/A" }

                # Match adapter driver for version and date
                $driverInfo = $allDrivers | Where-Object { $_.DeviceID -eq $adapter.PNPDeviceID }
                $driverVersion = $driverInfo.DriverVersion
                $driverDate = if ($driverInfo.DriverDate -match "^\d{8}")
                { 
                    [datetime]::ParseExact($driverInfo.DriverDate.Substring(0, 8), "yyyyMMdd", $null).ToShortDateString() 
                }
                else
                { 
                    "N/A" 
                }

                # Adapter-level QoS
                $adapterQosEnabled = "N/A"
                if ($adapter.PhysicalAdapter -eq $true -and $adapter.NetConnectionStatus -eq 2 -and !$adapter.NetConnectionID.StartsWith("vEthernet"))
                {
                    try
                    {
                        $adapterQos = Get-NetAdapterQos -Name $adapter.NetConnectionID -CimSession $node.Name
                        $adapterQosEnabled = $adapterQos.Enabled
                    }
                    catch
                    {
                        Write-Log "Failed to retrieve QoS settings for adapter: $($adapter.NetConnectionID) on $($nodeName): $_"
                    }
                }

                # RDMA settings for physical connected adapters
                if ($adapter.PhysicalAdapter -eq $true -and $adapter.NetConnectionStatus -eq 2 -and !$adapter.NetConnectionID.StartsWith("vEthernet"))
                {
                    try
                    {
                        $rdmaInfo = Get-NetAdapterRdma -Name $adapter.NetConnectionID -CimSession $node.Name
                    }
                    catch
                    {
                        Write-Log "Failed to retrieve RDMA settings for adapter: $($adapter.NetConnectionID) on $($nodeName): $_"
                    }
                }

                # Add network adapter details as a true object
                $networkAdapter = [pscustomobject]@{
                    NetAdapterName       = $adapter.NetConnectionID
                    InterfaceDescription = $adapter.Name
                    Status               = if ($adapter.NetConnectionStatus -eq 2) { "Connected" } else { "Disconnected" }
                    SpeedMbps            = if ($null -ne $adapter.Speed) { [math]::Round($adapter.Speed / 1MB, 2) } else { "N/A" }
                    IPAddress            = $ipAddress
                    MACAddress           = $adapter.MACAddress
                    DriverVersion        = $driverVersion
                    DriverDate           = $driverDate
                    PhysicalAdapter      = $adapter.PhysicalAdapter
                    ConnectedSwitch      = $connectedSwitch
                    QoSEnabled           = $adapterQosEnabled
                    RDMAEnabled          = $rdmainfo.Enabled
                    PFC                  = [string]$rdmaInfo.PFC
                    ETS                  = [string]$rdmaInfo.ETS
                }
                $networkAdapters += $networkAdapter
            }
            $networkAdapters = $networkAdapters | Sort-Object Status, IPAddress, NetAdapterName


            # Add node info including QoS settings to cluster's Nodes array
            $nodeInfo = [pscustomobject]@{
                Name              = $node.Name
                State             = $nodeState
                SocketCount       = $socketCount
                PhysicalCores     = $physicalCores
                LogicalCores      = $logicalCores
                HyperThreading    = $hyperThreading
                PhysicalMemoryMB  = [math]::Round($physicalMemory, 2)
                OSVersion         = $osVersion
                AvailableMemoryMB = [math]::Round($availableMemory, 2)
                NetworkAdapters   = $networkAdapters
                QoS               = $nodeQosSettings
            }
            $clusterInfo.Nodes += $nodeInfo
        }
        catch
        {
            Write-Log "Failed to retrieve data for node $($node.Name): $_"
        }
    }

    # Add the cluster object to the main array
    $clustersArray += $clusterInfo
}

# Wrap the cluster array in a top-level object for proper JSON structure
$clustersData = @{
    "clusters" = $clustersArray
}

$clustersData.Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

# Export to JSON for dashboard usage
$exportPath = "C:\SYSAdmin\PortalAggregator\AdminPortal-master\ClusterInfo.json"
$clustersData | ConvertTo-Json -Depth 10 | Out-File -FilePath $exportPath -Encoding UTF8

Write-Log "Cluster information exported to $exportPath in UTF-8 encoding"
