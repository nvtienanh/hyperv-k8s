$version = 'v1.0.3'
$workdir = "$HOME\Documents"
# $guestuser = $env:USERNAME.ToLower()
$guestuser = 'administrator'
$sshpath = "$HOME\Documents\ssh-key.pub"
if (!(Test-Path $sshpath)) {
  Write-Host "`n please configure `$sshpath or place a pubkey at $sshpath `n"
  exit
}
$sshpub = $(Get-Content $sshpath -raw).trim()

$config = $(Get-Content -path .\.distro -ea silentlycontinue | Out-String).trim()
if (!$config) {
  $config = 'focal'
}

switch ($config) {
  'bionic' {
    $distro = 'ubuntu'
    $generation = 2
    $imgvers = "18.04"
    $imagebase = "https://cloud-images.ubuntu.com/releases/server/$imgvers/release"
    $sha256file = 'SHA256SUMS'
    $image = "ubuntu-$imgvers-server-cloudimg-amd64.img"
    $archive = ""
  }
  'focal' {
    $distro = 'ubuntu'
    $generation = 2
    $imgvers = "20.04"
    $imagebase = "https://cloud-images.ubuntu.com/releases/server/$imgvers/release"
    $sha256file = 'SHA256SUMS'
    $image = "ubuntu-$imgvers-server-cloudimg-amd64.img"
    $archive = ""
  }
}

$nettype = 'private' # private/public
$zwitch = 'K8s' # private or public switch name
$natnet = 'KubeNatNet' # private net nat net name (privnet only)
$adapter = 'Wi-Fi' # public net adapter name (pubnet only)

$cpus = 1
$ram = '2GB'
$hdd = '20GB'

$cidr = switch ($nettype) {
  'private' { '10.10.0' }
  'public' { $null }
}

$macs = @(
  '0247F6C23539', # nfs1
  '02E1136852CD', # nfs2
  '0223FF85A7DB'  # nfs3
)

# ----------------------------------------------------------------------

$imageurl = "$imagebase/$image$archive"
$srcimg = "$workdir\$image"
$vhdxtmpl = "$workdir\$($image -replace '^(.+)\.[^.]+$', '$1').vhdx"


# switch to the script directory
Set-Location $PSScriptRoot | Out-Null

# stop on any error
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$etchosts = "$env:windir\System32\drivers\etc\hosts"

# note: network configs version 1 an 2 didn't work
function Get-Metadata($vmname, $cblock, $ip) {
  if (!$cblock) {
    return @"
instance-id: id-$($vmname)
local-hostname: $($vmname)
"@
  }
  else {
    return @"
instance-id: id-$vmname
network-interfaces: |
  auto eth0
  iface eth0 inet static
  address $($cblock).$($ip)
  network $($cblock).0
  netmask 255.255.255.0
  broadcast $($cblock).255
  gateway $($cblock).1
local-hostname: $vmname
"@
  }
}

function Get-UserdataShared($cblock) {
  return @"
#cloud-config

mounts:
  - [ swap ]

groups:
  - docker

users:
  - name: $guestuser
    ssh_authorized_keys:
$($sshpub.Replace("ssh-rsa","      - ssh-rsa"))
    sudo: [ 'ALL=(ALL) NOPASSWD:ALL' ]
    groups: [ sudo, docker ]
    shell: /bin/bash
    # lock_passwd: false # passwd won't work without this
    # passwd: '`$6`$rounds=4096`$byY3nxArmvpvOrpV`$2M4C8fh3ZXx10v91yzipFRng1EFXTRNDE3q9PvxiPc3kC7N/NHG8HiwAvhd7QjMgZAXOsuBD5nOs0AJkByYmf/' # 'test'

write_files:
  # resolv.conf hard-set is a workaround for intial setup
  - path: /etc/resolv.conf
    content: |
      nameserver 8.8.4.4
      nameserver 8.8.8.8
  - path: /etc/systemd/resolved.conf
    content: |
      [Resolve]
      DNS=8.8.4.4
      FallbackDNS=8.8.8.8
  - path: /tmp/append-etc-hosts
    content: |
      $(Set-HostsFile -cblock $cblock -prefix '      ')
  - path: /etc/modules-load.d/k8s.conf
    content: |
      br_netfilter
  - path: /etc/sysctl.d/k8s.conf
    content: |
      net.bridge.bridge-nf-call-ip6tables = 1
      net.bridge.bridge-nf-call-iptables = 1
      net.bridge.bridge-nf-call-arptables = 1
      net.ipv4.ip_forward = 1
  - path: /etc/docker/daemon.json
    content: |
      {
        "exec-opts": ["native.cgroupdriver=systemd"],
        "log-driver": "json-file",
        "log-opts": {
          "max-size": "100m"
        },
        "storage-driver": "overlay2",
        "storage-opts": [
          "overlay2.override_kernel_check=true"
        ]
      }
"@
}

function Get-UserdataUbuntu($cblock) {
return @"
$(Get-UserdataShared -cblock $cblock)
  - path: /etc/systemd/network/99-default.link
    content: |
      [Match]
      Path=/devices/virtual/net/*
      [Link]
      NamePolicy=kernel database onboard slot path
      MACAddressPolicy=none
  # https://github.com/clearlinux/distribution/issues/39
  - path: /etc/chrony/chrony.conf
    content: |
      refclock PHC /dev/ptp0 trust poll 2
      makestep 1 -1
      maxdistance 16.0
      #pool pool.ntp.org iburst
      driftfile /var/lib/chrony/chrony.drift
      logdir /var/log/chrony
package_upgrade: true
packages:
  - linux-tools-virtual
  - linux-cloud-tools-virtual
  - nfs-kernel-server
  - chrony
runcmd:
  - echo "sudo tail -f /var/log/syslog" > /home/$guestuser/log
  - systemctl mask --now systemd-timesyncd
  - systemctl enable --now chrony
  - cat /tmp/append-etc-hosts >> /etc/hosts
  - mkdir -p /usr/libexec/hypervkvpd && ln -s /usr/sbin/hv_get_dns_info /usr/sbin/hv_get_dhcp_info /usr/libexec/hypervkvpd
  - mkdir -p /mnt/nfs
  - mkdir -p /mnt/nfs/data
  - chown nobody:nogroup /mnt/nfs
  - chmod 777 /mnt/nfs
  - echo "/mnt/nfs $cidr.0/24(rw,sync,no_subtree_check,insecure,no_root_squash)" >> /etc/exports
  - exportfs -a
  - systemctl restart nfs-kernel-server
  - touch /home/$guestuser/.init-completed
power_state:
  timeout: 300
  mode: reboot
"@
}

function New-PublicNet($zwitch, $adapter) {
  New-VMSwitch -name $zwitch -allowmanagementos $true -netadaptername $adapter | Format-List
}

function New-PrivateNet($natnet, $zwitch, $cblock) {
  New-VMSwitch -name $zwitch -switchtype internal | Format-List
  New-NetIPAddress -ipaddress "$($cblock).1" -prefixlength 24 -interfacealias "vEthernet ($zwitch)" | Format-List
  New-NetNat -name $natnet -internalipinterfaceaddressprefix "$($cblock).0/24" | Format-List
}

function Write-YamlContents($path, $cblock) {
  Set-Content $path ([byte[]][char[]] `
      "$(&"get-userdata$distro" -cblock $cblock)`n") -encoding byte
}

function Write-ISOContents($vmname, $cblock, $ip) {
  mkdir $workdir\$vmname\cidata -ea 0 | Out-Null
  Set-Content $workdir\$vmname\cidata\meta-data ([byte[]][char[]] `
      "$(Get-Metadata -vmname $vmname -cblock $cblock -ip $ip)") -encoding byte
  Write-YamlContents -path $workdir\$vmname\cidata\user-data -cblock $cblock
}

function New-ISO($vmname) {
  $fsi = new-object -ComObject IMAPI2FS.MsftFileSystemImage
  $fsi.FileSystemsToCreate = 3
  $fsi.VolumeName = 'cidata'
  $vmdir = (resolve-path -path "$workdir\$vmname").path
  $path = "$vmdir\cidata"
  $fsi.Root.AddTreeWithNamedStreams($path, $false)
  $isopath = "$vmdir\$vmname.iso"
  $res = $fsi.CreateResultImage()
  $cp = New-Object CodeDom.Compiler.CompilerParameters
  $cp.CompilerOptions = "/unsafe"
  if (!('ISOFile' -as [type])) {
    Add-Type -CompilerParameters $cp -TypeDefinition @"
      public class ISOFile {
        public unsafe static void Create(string iso, object stream, int blkSz, int blkCnt) {
          int bytes = 0; byte[] buf = new byte[blkSz];
          var ptr = (System.IntPtr)(&bytes); var o = System.IO.File.OpenWrite(iso);
          var i = stream as System.Runtime.InteropServices.ComTypes.IStream;
          if (o != null) { while (blkCnt-- > 0) { i.Read(buf, blkSz, ptr); o.Write(buf, 0, bytes); }
            o.Flush(); o.Close(); }}}
"@ 
  }
  [ISOFile]::Create($isopath, $res.ImageStream, $res.BlockSize, $res.TotalBlocks)
}

function New-Machine($zwitch, $vmname, $cpus, $mem, $hdd, $vhdxtmpl, $cblock, $ip, $mac) {
  $vmdir = "$workdir\$vmname"
  $vhdx = "$workdir\$vmname\$vmname.vhdx"

  New-Item -itemtype directory -force -path $vmdir | Out-Null

  if (!(Test-Path $vhdx)) {
    Copy-Item -path $vhdxtmpl -destination $vhdx -force
    Resize-VHD -path $vhdx -sizebytes $hdd

    Write-ISOContents -vmname $vmname -cblock $cblock -ip $ip
    # New-ISO -vmname $vmname
    Copy-Item "$workdir\isos\$vmname.iso" -Destination "$workdir\$vmname"

    $vm = New-VM -name $vmname -memorystartupbytes $mem -generation $generation `
      -switchname $zwitch -vhdpath $vhdx -path $workdir

    if ($generation -eq 2) {
      Set-VMFirmware -vm $vm -enablesecureboot off
    }

    Set-VMProcessor -vm $vm -count $cpus
    Add-VMDvdDrive -vmname $vmname -path $workdir\$vmname\$vmname.iso

    if (!$mac) { $mac = New-MacAddress }

    Get-VMNetworkAdapter -vm $vm | Set-VMNetworkAdapter -staticmacaddress $mac
    Set-VMComPort -vmname $vmname -number 2 -path \\.\pipe\$vmname
  }
  Start-VM -name $vmname
}

# Write ISO file to local machine
function Write-ISO($zwitch, $vmname, $cpus, $mem, $hdd, $vhdxtmpl, $cblock, $ip, $mac) {
  $vmdir = "$workdir\$vmname"
  $vhdx = "$workdir\$vmname\$vmname.vhdx"
  New-Item -itemtype directory -force -path $vmdir | Out-Null
  if (!(Test-Path $vhdx)) {
    Copy-Item -path $vhdxtmpl -destination $vhdx -force
    Resize-VHD -path $vhdx -sizebytes $hdd

    Write-ISOContents -vmname $vmname -cblock $cblock -ip $ip
    New-ISO -vmname $vmname
  }
}

function Remove-Machine($name) {
  Stop-VM $name -turnoff -confirm:$false -ea silentlycontinue
  Remove-VM $name -force -ea silentlycontinue
  Remove-Item -recurse -force $workdir\$name
}

function Remove-PublicNet($zwitch) {
  Remove-VMswitch -name $zwitch -force -confirm:$false
}

function Remove-PrivateNet($zwitch, $natnet) {
  Remove-VMswitch -name $zwitch -force -confirm:$false
  Remove-NetNat -name $natnet -confirm:$false
}

function New-MacAddress() {
  return "02$((1..5 | ForEach-Object { '{0:X2}' -f (get-random -max 256) }) -join '')"
}

function basename($path) {
  return $path.substring(0, $path.lastindexof('.'))
}

function New-VHDXTmpl($imageurl, $srcimg, $vhdxtmpl) {
  if (!(Test-Path $workdir)) {
    mkdir $workdir | Out-Null
  }
  if (!(Test-Path $srcimg$archive)) {
    Get-File -url $imageurl -saveto $srcimg$archive
  }

  Get-Item -path $srcimg$archive | ForEach-Object { Write-Host 'srcimg:', $_.name, ([math]::round($_.length / 1MB, 2)), 'MB' }

  if ($sha256file) {
    $hash = shasum256 -shaurl "$imagebase/$sha256file" -diskitem $srcimg$archive -item $image$archive
    Write-Output "checksum: $hash"
  }
  else {
    Write-Output "no sha256file specified, skipping integrity ckeck"
  }

  if (($archive -eq '.tar.gz') -and (!(Test-Path $srcimg))) {
    tar xzf $srcimg$archive -C $workdir
  }
  elseif (($archive -eq '.xz') -and (!(Test-Path $srcimg))) {
    7z e $srcimg$archive "-o$workdir"
  }
  elseif (($archive -eq '.bz2') -and (!(Test-Path $srcimg))) {
    7z e $srcimg$archive "-o$workdir"
  }

  if (!(Test-Path $vhdxtmpl)) {
    qemu-img.exe convert $srcimg -O vhdx -o subformat=dynamic $vhdxtmpl
  }

  Write-Output ''
  Get-Item -path $vhdxtmpl | ForEach-Object { Write-Host 'vhxdtmpl:', $_.name, ([math]::round($_.length / 1MB, 2)), 'MB' }
  return
}

function Get-File($url, $saveto) {
  Write-Output "downloading $url to $saveto"
  $progresspreference = 'silentlycontinue'
  Invoke-Webrequest $url -usebasicparsing -outfile $saveto # too slow w/ indicator
  $progresspreference = 'continue'
}

function Set-HostsFile($cblock, $prefix) {
  $ret = switch ($nettype) {
    'private' {
      @"
#
$prefix#
$prefix$($cblock).101 nfs1
$prefix$($cblock).102 nfs2
$prefix$($cblock).103 nfs3
$prefix#
$prefix#
"@
    }
    'public' {
      ''
    }
  }
  return $ret
}

function Update-HostsFile($cblock) {
  Set-HostsFile -cblock $cblock -prefix '' | Out-File -encoding utf8 -append $etchosts
  Get-Content $etchosts
}

function New-NFSVMs($num, $cblock) {
  1..$num | ForEach-Object {
    Write-Output creating nfs server $_
    New-Machine -zwitch $zwitch -vmname "nfs$_" -cpus 4 -mem 4GB -hdd 40GB `
      -vhdxtmpl $vhdxtmpl -cblock $cblock -ip $(10 + $_)
  }
}

function Remove-NFSVMs($num) {
  1..$num | ForEach-Object {
    Write-Output deleting nfs server $_
    Remove-Machine -name "nfs$_"
  }
}

function Get-NFSVM() {
  return get-vm | Where-Object { ($_.name -match 'nfs.*') }
}

function get-our-running-vms() {
  return get-vm | Where-Object { ($_.state -eq 'running') -and ($_.name -match 'nfs.*') }
}

function shasum256($shaurl, $diskitem, $item) {
  $pat = "^(\S+)\s+\*?$([regex]::escape($item))$"

  $hash = Get-Filehash -algo sha256 -path $diskitem | ForEach-Object { $_.hash }

  $webhash = ( Invoke-Webrequest $shaurl -usebasicparsing ).tostring().split("`n") | `
    Select-String $pat | ForEach-Object { $_.matches.groups[1].value }

  if (!($hash -ieq $webhash)) {
    throw @"
    SHA256 MISMATCH:
       shaurl: $shaurl
         item: $item
     diskitem: $diskitem
     diskhash: $hash
      webhash: $webhash
"@
  }
  return $hash
}

function Get-Ctrlc() {
  if ([console]::KeyAvailable) {
    $key = [system.console]::readkey($true)
    if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
      return $true
    }
  }
  return $false;
}

function Wait-NodeInit($opts, $name) {
  while ( ! $(ssh $opts $guestuser@master 'ls ~/.init-completed 2> /dev/null') ) {
    Write-Output "waiting for $name to init..."
    Start-Sleep -seconds 5
    if ( Get-Ctrlc ) { exit 1 }
  }
}

function Convert-UNCPath($path) {
  $item = Get-Item $path
  return $path.replace($item.root, '/').replace('\', '/')
}

function Convert-UNCPath2($path) {
  return ($path -replace '^[^:]*:?(.+)$', "`$1").replace('\', '/')
}

Write-Output ''

if ($args.count -eq 0) {
  $args = @( 'help' )
}

switch -regex ($args) {
  ^help$ {
    Write-Output @"
  Practice real Kubernetes configurations on a local multi-node cluster.
  Inspect and optionally customize this script before use.

  Usage: .\hyperv-nfs.ps1 command+

  Commands:

         Show-Config - Show script config vars
      Deploy-Network - Install private or public host network
    Deploy-HostsFile - Append private network node names to etc/hosts
           Get-Image - Download the VM image
       Deploy-Master - Create and launch master node
         Deploy-NFSN - Create and launch NFS VM (NFS1, NFS2, ...)
      Save-ISOMaster - Save master node iso
        Save-ISONFSN - Save NFS iso (NFS1, NFS2, ...)
            Get-Info - Display info about nodes
       Restart-NFSVM - Soft-reboot the nodes
     Invoke-Shutdown - Soft-shutdown the nodes
          Save-NFSVM - Snapshot the VMs
       Restore-NFSVM - Restore VMs from latest snapshots
          Stop-NFSVM - Stop the VMs
         Start-NFSVM - Start the VMs
        Remove-NFSVM - Stop VMs and delete the VM files
      Remove-Network - Delete the network
"@
  }
  ^Deploy-Network$ {
    switch ($nettype) {
      'private' { New-PrivateNet -natnet $natnet -zwitch $zwitch -cblock $cidr }
      'public' { New-PublicNet -zwitch $zwitch -adapter $adapter }
    }
  }
  ^Deploy-HostsFile$ {
    switch ($nettype) {
      'private' { Update-HostsFile -cblock $cidr }
      'public' { Write-Output "not supported for public net - use dhcp" }
    }
  }
  ^Show-Macs$ {
    $cnt = 10
    0..$cnt | ForEach-Object {
      $comment = switch ($_) { 0 { 'master' } default { "nfs$_" } }
      $comma = if ($_ -eq $cnt) { '' } else { ',' }
      Write-Output "  '$(New-MacAddress)'$comma # $comment"
    }
  }
  ^Get-Image$ {
    New-VHDXTmpl -imageurl $imageurl -srcimg $srcimg -vhdxtmpl $vhdxtmpl
  }
  '(^Deploy-NFS(?<number>\d+)$)' {
    $num = [int]$matches.number
    $name = "nfs$($num)"
    New-Machine -zwitch $zwitch -vmname $name -cpus $cpus `
      -mem $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) `
      -vhdxtmpl $vhdxtmpl -cblock $cidr -ip "$($num + 100)" -mac $macs[$num]
  }
  '(^Save-ISONFS(?<number>\d+)$)' {
    $num = [int]$matches.number
    $name = "nfs$($num)"
    Write-ISO -zwitch $zwitch -vmname $name -cpus $cpus `
      -mem $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) `
      -vhdxtmpl $vhdxtmpl -cblock $cidr -ip "$($num + 100)" -mac $macs[$num]
  }
  ^Get-Info$ {
    Get-NFSVM
  }  
  ^Restart-NFSVM$ {
    Get-NFSVM | ForEach-Object { $node = $_.name; $(ssh $sshopts $guestuser@$node 'sudo reboot') }
  }
  ^Invoke-Shutdown$ {
    Get-NFSVM | ForEach-Object { $node = $_.name; $(ssh $sshopts $guestuser@$node 'sudo shutdown -h now') }
  }
  ^Save-NFSVM$ {
    Get-NFSVM | Checkpoint-VM
  }
  ^Restore-NFSVM$ {
    Get-NFSVM | Foreach-Object { $_ | Get-VMSnapshot | Sort-Object creationtime | `
        Select-Object -last 1 | Restore-VMSnapshot -confirm:$false }
  }
  ^Stop-NFSVM$ {
    Get-NFSVM | Stop-VM
  }
  ^Start-NFSVM$ {
    Get-NFSVM | Start-VM
  }
  ^Remove-NFSVM$ {
    Get-NFSVM | ForEach-Object { Remove-Machine -name $_.name }
  }
  ^Remove-Network$ {
    switch ($nettype) {
      'private' { Remove-PrivateNet -zwitch $zwitch -natnet $natnet }
      'public' { Remove-PublicNet -zwitch $zwitch }
    }
  }
  ^Get-Time$ {
    Write-Output "local: $(Get-date)"
    Get-NFSVM | ForEach-Object {
      $node = $_.name
      Write-Output ---------------------$node
      # ssh $sshopts $guestuser@$node "date ; if which chronyc > /dev/null; then sudo chronyc makestep ; date; fi"
      ssh $sshopts $guestuser@$node "date"
    }
  }
  ^Start-Track$ {
    Get-NFSVM | ForEach-Object {
      $node = $_.name
      Write-Output ---------------------$node
      ssh $sshopts $guestuser@$node "date ; sudo chronyc tracking"
    }
  }
  default {
    Write-Output 'invalid command; try: .\hyperv-nfs.ps1 help'
  }
}

Write-Output ''
