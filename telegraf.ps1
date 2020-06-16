Function Send-JsonOverTcp {
    param ( [ValidateNotNullOrEmpty()] 
    [string] $Ip, 
    [int] $Port, 
    $JsonObject) 
    $JsonString = $JsonObject -replace "`n",' ' -replace "`r",' ' -replace ' ',''
    $Socket = New-Object System.Net.Sockets.TCPClient($Ip,$Port) 
    $Stream = $Socket.GetStream() 
    $Writer = New-Object System.IO.StreamWriter($Stream)
    $Writer.WriteLine($JsonString)
    $Writer.Flush()
    $Stream.Close()
    $Socket.Close()
}

#Get VM Info
$vms = Get-VM | where {$_.state -eq "Running"}
foreach ($vm in $vms ){
  $name = $vm.Name
  IF($vm.DynamicMemoryEnabled){
    $Memory      = $vm.MemoryMaximum           
  }ELSE{
    $Memory      = $vm.MemoryAssigned         
  }
  $vhds = Get-VM -VMName $name | Select-Object VMId | Get-VHD
  $size = 0
  foreach($vhd in $vhds){
    If($vhd.parentpath){
      $size += ($vhd.parentpath | Get-VHD).filesize
    }ELSE{
      $size += $vhd.filesize
    }
  }
  IF(Get-vmsnapshot -vmname $vm.name){$snapshot= "True"}ELSE{$snapshot = "False"}
  $obj = New-Object PSObject -Property @{
    FriendlyName  = $name
    vCPU	        = $vm.ProcessorCount
    Memory	      = ($memory)/1024/1024
    DiskSize	    = ($size)/1024/1024
    DiskCount     = $vm.HardDrives.count
    NICS          = $vm.NetworkAdapters.count
  }
  $vmstats = $obj | Select-Object FriendlyName,@{ Label = "vCPU" ; Expression = { ($_.vCPU) } },@{ Label = "Memory(MB)" ; Expression = { ($_.Memory) } },@{ Label = "DiskSize(MB)" ; Expression = {  ($_.DiskSize) } },@{ Label = "DiskCount" ; Expression = {  ($_.DiskCount) }},@{ Label = "NICS" ; Expression = {  ($_.NICS) }} | ConvertTo-Json
   Send-JsonOverTcp 127.0.0.1 8094 "$vmstats"
   
  # VM Health & State
  $obj = New-Object PSObject -Property @{
    FriendlyName  = $name
    ReplicaHealth = $vm.ReplicationHealth
    ReplicaState  = $vm.ReplicationState
    Snapshot      = $snapshot
    Heartbeat     = $vm.Heartbeat
    State         = $vm.State
    Generation    = $vm.Generation
    IsClustered   = $vm.IsClustered
    
  }
  $vminfo = $obj | Select-Object FriendlyName,ReplicaHealth,ReplicaState,Snapshot,Heartbeat,State,Generation,IsClustered | ConvertTo-Json
   Send-JsonOverTcp 127.0.0.1 8094 "$vminfo"
}

