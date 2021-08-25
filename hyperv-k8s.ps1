$version = 'v1.0.3'
$workdir = "$HOME\Documents"
# $guestuser = $env:USERNAME.ToLower()
$guestuser = 'administrator'
$sshpath = "$HOME\.ssh\id_rsa.pub"
if (!(test-path $sshpath)) {
  write-host "`n please configure `$sshpath or place a pubkey at $sshpath `n"
  exit
}
$sshpub = $(get-content $sshpath -raw).trim()

$config = $(get-content -path .\.distro -ea silentlycontinue | out-string).trim()
if(!$config) {
  $config = 'focal'
}

switch ($config) {
  'bionic' {
    $distro = 'ubuntu'
    $generation = 2
    $imgvers="18.04"
    $imagebase = "https://cloud-images.ubuntu.com/releases/server/$imgvers/release"
    $sha256file = 'SHA256SUMS'
    $image = "ubuntu-$imgvers-server-cloudimg-amd64.img"
    $archive = ""
  }
  'focal' {
    $distro = 'ubuntu'
    $generation = 2
    $imgvers="20.04"
    $imagebase = "https://cloud-images.ubuntu.com/releases/server/$imgvers/release"
    $sha256file = 'SHA256SUMS'
    $image = "ubuntu-$imgvers-server-cloudimg-amd64.img"
    $archive = ""
  }
}

$nettype = 'private' # private/public
$zwitch = 'k8s' # private or public switch name
$natnet = 'kubenatnet' # private net nat net name (privnet only)
$adapter = 'Wi-Fi' # public net adapter name (pubnet only)

$cpus = 2
$ram = '2GB'
$hdd = '20GB'

$cidr = switch ($nettype) {
  'private' { '10.10.0' }
  'public' { $null }
}

$macs = @(
  '0225EA2C9AE7', # master
  '02A254C4612F', # node1
  '02FBB5136210', # node2
  '02FE66735ED6', # node3
  '021349558DC7', # node4
  '0288F589DCC3', # node5
  '02EF3D3E1283', # node6
  '0225849ADCBB', # node7
  '02E0B0026505', # node8
  '02069FBFC2B0', # node9
  '02F7E0C904D0' # node10
)

# https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64/repodata/filelists.xml
# https://packages.cloud.google.com/apt/dists/kubernetes-xenial/main/binary-amd64/Packages
# ctrl+f "kubeadm"
$kubeversion = '1.22.1-00'

$kubepackages = @"
  - docker-ce
  - [ kubelet, $kubeversion ]
  - [ kubeadm, $kubeversion ]
  - [ kubectl, $kubeversion ]
"@

$cni = 'flannel'

switch ($cni) {
  'flannel' {
    $cniyaml = 'https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml'
    $cninet = '10.244.0.0/16'
  }
  'weave' {
    $cniyaml = 'https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d "\n")'
    $cninet = '10.32.0.0/12'
  }
  'calico' {
    $cniyaml = 'https://docs.projectcalico.org/v3.7/manifests/calico.yaml'
    $cninet = '192.168.0.0/16'
  }
}

$sshopts = @('-o LogLevel=ERROR', '-o StrictHostKeyChecking=no', '-o UserKnownHostsFile=/dev/null')

$dockercli = 'https://github.com/StefanScherer/docker-cli-builder/releases/download/20.10.5/docker.exe'

$helmurl = 'https://get.helm.sh/helm-v3.1.2-windows-amd64.zip'

# ----------------------------------------------------------------------

$imageurl = "$imagebase/$image$archive"
$srcimg = "$workdir\$image"
$vhdxtmpl = "$workdir\$($image -replace '^(.+)\.[^.]+$', '$1').vhdx"


# switch to the script directory
Set-Location $PSScriptRoot | out-null

# stop on any error
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction']='Stop'

$etchosts = "$env:windir\System32\drivers\etc\hosts"

# note: network configs version 1 an 2 didn't work
function get-metadata($vmname, $cblock, $ip) {
if(!$cblock) {
return @"
instance-id: id-$($vmname)
local-hostname: $($vmname)
"@
} else {
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

function get-userdata-shared($cblock) {
return @"
#cloud-config

mounts:
  - [ swap ]

groups:
  - docker

users:
  - name: $guestuser
    ssh_authorized_keys:
      - $($sshpub)
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
      $(set-etc-hosts -cblock $cblock -prefix '      ')
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

function get-userdata-ubuntu($cblock) {
return @"
$(get-userdata-shared -cblock $cblock)
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
apt:
  sources:
    kubernetes:
      source: "deb http://apt.kubernetes.io/ kubernetes-xenial main"
      keyserver: "hkp://keyserver.ubuntu.com:80"
      keyid: 307EA071
    docker:
      arches: amd64
      source: "deb https://download.docker.com/linux/ubuntu $config stable"
      keyserver: "hkp://keyserver.ubuntu.com:80"
      keyid: 0EBFCD88

package_upgrade: true

packages:
  - linux-tools-virtual
  - linux-cloud-tools-virtual
  - nfs-common
  - chrony
$kubepackages

runcmd:
  - echo "sudo tail -f /var/log/syslog" > /home/$guestuser/log
  - systemctl mask --now systemd-timesyncd
  - systemctl enable --now chrony
  - systemctl stop kubelet
  - cat /tmp/append-etc-hosts >> /etc/hosts
  - mkdir -p /usr/libexec/hypervkvpd && ln -s /usr/sbin/hv_get_dns_info /usr/sbin/hv_get_dhcp_info /usr/libexec/hypervkvpd
  - chmod o+r /lib/systemd/system/kubelet.service
  - chmod o+r /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
  # https://github.com/kubernetes/kubeadm/issues/954
  - apt-mark hold kubeadm kubelet kubectl
  - touch /home/$guestuser/.init-completed

power_state:
  timeout: 300
  mode: reboot
"@
}

function new-public-net($zwitch, $adapter) {
  new-vmswitch -name $zwitch -allowmanagementos $true -netadaptername $adapter | format-list
}

function new-private-net($natnet, $zwitch, $cblock) {
  new-vmswitch -name $zwitch -switchtype internal | format-list
  new-netipaddress -ipaddress "$($cblock).1" -prefixlength 24 -interfacealias "vEthernet ($zwitch)" | format-list
  new-netnat -name $natnet -internalipinterfaceaddressprefix "$($cblock).0/24" | format-list
}

function write-yaml-contents($path, $cblock) {
  set-content $path ([byte[]][char[]] `
    "$(&"get-userdata-$distro" -cblock $cblock)`n") -encoding byte
}

function write-iso-contents($vmname, $cblock, $ip) {
  mkdir $workdir\$vmname\cidata -ea 0 | out-null
  set-content $workdir\$vmname\cidata\meta-data ([byte[]][char[]] `
    "$(get-metadata -vmname $vmname -cblock $cblock -ip $ip)") -encoding byte
  write-yaml-contents -path $workdir\$vmname\cidata\user-data -cblock $cblock
}

function new-iso($vmname) {
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
"@ }
  [ISOFile]::Create($isopath, $res.ImageStream, $res.BlockSize, $res.TotalBlocks)
}

function new-machine($zwitch, $vmname, $cpus, $mem, $hdd, $vhdxtmpl, $cblock, $ip, $mac) {
  $vmdir = "$workdir\$vmname"
  $vhdx = "$workdir\$vmname\$vmname.vhdx"

  new-item -itemtype directory -force -path $vmdir | out-null

  if (!(test-path $vhdx)) {
    copy-item -path $vhdxtmpl -destination $vhdx -force
    resize-vhd -path $vhdx -sizebytes $hdd

    write-iso-contents -vmname $vmname -cblock $cblock -ip $ip
    # new-iso -vmname $vmname
    Copy-Item "$workdir\isos\$vmname.iso" -Destination "$workdir\$vmname"

    $vm = new-vm -name $vmname -memorystartupbytes $mem -generation $generation `
      -switchname $zwitch -vhdpath $vhdx -path $workdir

    if($generation -eq 2) {
      set-vmfirmware -vm $vm -enablesecureboot off
    }

    set-vmprocessor -vm $vm -count $cpus
    add-vmdvddrive -vmname $vmname -path $workdir\$vmname\$vmname.iso

    if(!$mac) { $mac = new-mac-address }

    get-vmnetworkadapter -vm $vm | set-vmnetworkadapter -staticmacaddress $mac
    set-vmcomport -vmname $vmname -number 2 -path \\.\pipe\$vmname
  }
  start-vm -name $vmname
}

# Write ISO file to local machine
function write-iso-file($zwitch, $vmname, $cpus, $mem, $hdd, $vhdxtmpl, $cblock, $ip, $mac) {
  $vmdir = "$workdir\$vmname"
  $vhdx = "$workdir\$vmname\$vmname.vhdx"
  new-item -itemtype directory -force -path $vmdir | out-null
  if (!(test-path $vhdx)) {
    copy-item -path $vhdxtmpl -destination $vhdx -force
    resize-vhd -path $vhdx -sizebytes $hdd

    write-iso-contents -vmname $vmname -cblock $cblock -ip $ip
    new-iso -vmname $vmname
  }
}

function remove-machine($name) {
  stop-vm $name -turnoff -confirm:$false -ea silentlycontinue
  remove-vm $name -force -ea silentlycontinue
  remove-item -recurse -force $workdir\$name
}

function remove-public-net($zwitch) {
  remove-vmswitch -name $zwitch -force -confirm:$false
}

function remove-private-net($zwitch, $natnet) {
  remove-vmswitch -name $zwitch -force -confirm:$false
  remove-netnat -name $natnet -confirm:$false
}

function new-mac-address() {
  return "02$((1..5 | ForEach-Object { '{0:X2}' -f (get-random -max 256) }) -join '')"
}

function basename($path) {
  return $path.substring(0, $path.lastindexof('.'))
}

function new-vhdx-tmpl($imageurl, $srcimg, $vhdxtmpl) {
  if (!(test-path $workdir)) {
    mkdir $workdir | out-null
  }
  if (!(test-path $srcimg$archive)) {
    get-file -url $imageurl -saveto $srcimg$archive
  }

  get-item -path $srcimg$archive | ForEach-Object { write-host 'srcimg:', $_.name, ([math]::round($_.length/1MB, 2)), 'MB' }

  if($sha256file) {
    $hash = shasum256 -shaurl "$imagebase/$sha256file" -diskitem $srcimg$archive -item $image$archive
    Write-Output "checksum: $hash"
  }
  else {
    Write-Output "no sha256file specified, skipping integrity ckeck"
  }

  if(($archive -eq '.tar.gz') -and (!(test-path $srcimg))) {
    tar xzf $srcimg$archive -C $workdir
  }
  elseif(($archive -eq '.xz') -and (!(test-path $srcimg))) {
    7z e $srcimg$archive "-o$workdir"
  }
  elseif(($archive -eq '.bz2') -and (!(test-path $srcimg))) {
    7z e $srcimg$archive "-o$workdir"
  }

  if (!(test-path $vhdxtmpl)) {
    qemu-img.exe convert $srcimg -O vhdx -o subformat=dynamic $vhdxtmpl
  }

  Write-Output ''
  get-item -path $vhdxtmpl | ForEach-Object { write-host 'vhxdtmpl:', $_.name, ([math]::round($_.length/1MB, 2)), 'MB' }
  return
}

function get-file($url, $saveto) {
  Write-Output "downloading $url to $saveto"
  $progresspreference = 'silentlycontinue'
  invoke-webrequest $url -usebasicparsing -outfile $saveto # too slow w/ indicator
  $progresspreference = 'continue'
}

function set-etc-hosts($cblock, $prefix) {
  $ret = switch ($nettype) {
    'private' {
@"
#
$prefix#
$prefix$($cblock).10 master
$prefix$($cblock).11 node1
$prefix$($cblock).12 node2
$prefix$($cblock).13 node3
$prefix$($cblock).14 node4
$prefix$($cblock).15 node5
$prefix$($cblock).16 node6
$prefix$($cblock).17 node7
$prefix$($cblock).18 node8
$prefix$($cblock).19 node9
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

function update-etc-hosts($cblock) {
  set-etc-hosts -cblock $cblock -prefix '' | out-file -encoding utf8 -append $etchosts
  get-content $etchosts
}

function new-nodes($num, $cblock) {
  1..$num | ForEach-Object {
    Write-Output creating node $_
    new-machine -zwitch $zwitch -vmname "node$_" -cpus 4 -mem 4GB -hdd 40GB `
      -vhdxtmpl $vhdxtmpl -cblock $cblock -ip $(10+$_)
  }
}

function remove-nodes($num) {
  1..$num | ForEach-Object {
    Write-Output deleting node $_
    remove-machine -name "node$_"
  }
}

function get-our-vms() {
  return get-vm | where-object { ($_.name -match 'master|node.*') }
}

function get-our-running-vms() {
  return get-vm | where-object { ($_.state -eq 'running') -and ($_.name -match 'master|node.*') }
}

function shasum256($shaurl, $diskitem, $item) {
  $pat = "^(\S+)\s+\*?$([regex]::escape($item))$"

  $hash = get-filehash -algo sha256 -path $diskitem | ForEach-Object { $_.hash}

  $webhash = ( invoke-webrequest $shaurl -usebasicparsing ).tostring().split("`n") | `
    select-string $pat | ForEach-Object { $_.matches.groups[1].value }

  if(!($hash -ieq $webhash)) {
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

function get-ctrlc() {
  if ([console]::KeyAvailable) {
    $key = [system.console]::readkey($true)
    if (($key.modifiers -band [consolemodifiers]"control") -and ($key.key -eq "C")) {
      return $true
    }
  }
  return $false;
}

function wait-for-node-init($opts, $name) {
  while ( ! $(ssh $opts $guestuser@master 'ls ~/.init-completed 2> /dev/null') ) {
    Write-Output "waiting for $name to init..."
    start-sleep -seconds 5
    if( get-ctrlc ) { exit 1 }
  }
}

function convert-unc-path($path) {
  $item = get-item $path
  return $path.replace($item.root, '/').replace('\', '/')
}

function convert-unc-path2($path) {
  return ($path -replace '^[^:]*:?(.+)$', "`$1").replace('\', '/')
}

function hyperctl() {
  kubectl --kubeconfig=$HOME/.kube/config.hyperctl $args
}

function show-aliases($pwsalias, $bashalias) {
  Write-Output ""
  Write-Output "powershell alias:"
  Write-Output "  write-output '$pwsalias' | out-file -encoding utf8 -append `$profile"
  Write-Output ""
  Write-Output "bash alias:"
  Write-Output "  write-output `"``n$($bashalias.replace('\', '\\'))``n`" | out-file -encoding utf8 -append -nonewline ~\.profile"
  Write-Output ""
  Write-Output "  -> restart your shell after applying the above"
}

function initialize-kubeconfig() {
  new-item -itemtype directory -force -path $HOME\.kube | out-null
  scp $sshopts $guestuser@master:.kube/config $HOME\.kube\config

  $cachedir="$HOME\.kube\cache\discovery\$cidr.10_6443"
  if (test-path $cachedir) {
    Write-Output ""
    Write-Output "deleting previous $cachedir"
    Write-Output ""
    Remove-Item $cachedir -recurse
  }

  Write-Output "executing: kubectl get pods --all-namespaces`n"
  kubectl get pods --all-namespaces
  Write-Output ""
  Write-Output "executing: kubectl get nodes`n"
  kubectl get nodes
}

function install-helm() {
  if (!(get-command "helm" -ea silentlycontinue)) {
    choco install -y kubernetes-helm
  }
  else {
    choco upgrade kubernetes-helm
  }

  Write-Output ""
  Write-Output "helm version: $(helm version)"

  $helm = "helm --kubeconfig $(convert-unc-path2 $HOME\.kube\config.hyperctl)"
  $pwsalias = "function hyperhelm() { $helm `$args }"
  $bashalias = "alias hyperhelm='$helm'"

  show-aliases -pwsalias $pwsalias -bashalias $bashalias
  Write-Output "  -> then you can use e.g.: hyperhelm version"
}

function show-local-repo-tips() {
Write-Output @"
# you can now publish your apps, e.g.:

TAG=master:30699/yourapp:`$(git log --pretty=format:'%h' -n 1)
docker build ../yourapp/image/ --tag `$TAG
docker push `$TAG
hyperhelm install yourapp ../yourapp/chart/ --set image=`$TAG
"@
}

Write-Output ''

if($args.count -eq 0) {
  $args = @( 'help' )
}

switch -regex ($args) {
  ^help$ {
    Write-Output @"
  Practice real Kubernetes configurations on a local multi-node cluster.
  Inspect and optionally customize this script before use.

  Usage: .\hyperctl.ps1 command+

  Commands:

     (pre-requisites are marked with ->)

  -> install - install basic chocolatey packages
      config - show script config vars
       print - print etc/hosts, network interfaces and mac addresses
  ->     net - install private or public host network
  ->   hosts - append private network node names to etc/hosts
  ->   image - download the VM image
      master - create and launch master node
       nodeN - create and launch worker node (node1, node2, ...)
        info - display info about nodes
        init - initialize k8s and setup host kubectl
      reboot - soft-reboot the nodes
    shutdown - soft-shutdown the nodes
        save - snapshot the VMs
     restore - restore VMs from latest snapshots
        stop - stop the VMs
       start - start the VMs
      delete - stop VMs and delete the VM files
      delnet - delete the network
         iso - write cloud config data into a local yaml
      docker - setup local docker with the master node
       share - setup local fs sharing with docker on master
       helm2 - setup helm 2 with tiller in k8s
       helm3 - setup helm 3
        repo - install local docker repo in k8s

  For more info, see: https://github.com/youurayy/hyperctl
"@
  }
  ^install$ {
    # Install qemu-img
    if (Test-Path 'C:\qemu-img') {
      Remove-Item 'C:\qemu-img' -Force -Recurse
    }
    Invoke-WebRequest -Uri 'https://cloudbase.it/downloads/qemu-img-win-x64-2_3_0.zip' -OutFile 'C:\qemu-img.zip'
    Expand-Archive -LiteralPath 'C:\qemu-img.zip' -DestinationPath C:\qemu-img
    Remove-Item 'C:\qemu-img.zip'

    # Install kubectl
    if (Test-Path 'C:\kubectl') {
      Remove-Item 'C:\kubectl' -Force -Recurse
    }
    New-Item -Path "C:\" -Name "kubectl" -ItemType "directory"
    Invoke-WebRequest -Uri 'https://dl.k8s.io/release/v1.22.0/bin/windows/amd64/kubectl.exe' -OutFile 'c:\kubectl\kubectl.exe'

    # Install docker cli
    if (Test-Path 'C:\docker') {
      Remove-Item 'C:\docker' -Force -Recurse
    }
    New-Item -Path "C:\" -Name "docker" -ItemType "directory"
    Invoke-WebRequest -Uri 'https://github.com/StefanScherer/docker-cli-builder/releases/download/20.10.5/docker.exe' -OutFile 'c:\docker\docker.exe'

    # Add to PATH
    $oldPath = Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment'
    $newPath = "$oldPath;C:\kubectl;C:\git\bin;C:\docker;C:\qemu-img"
    Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") 
  }
  ^config$ {
    Write-Output "   version: $version"
    Write-Output "    config: $config"
    Write-Output "    distro: $distro"
    Write-Output "   workdir: $workdir"
    Write-Output " guestuser: $guestuser"
    Write-Output "   sshpath: $sshpath"
    Write-Output "  imageurl: $imageurl"
    Write-Output "  vhdxtmpl: $vhdxtmpl"
    Write-Output "      cidr: $cidr.0/24"
    Write-Output "    switch: $zwitch"
    Write-Output "   nettype: $nettype"
    switch ($nettype) {
      'private' { Write-Output "    natnet: $natnet" }
      'public'  { Write-Output "   adapter: $adapter" }
    }
    Write-Output "      cpus: $cpus"
    Write-Output "       ram: $ram"
    Write-Output "       hdd: $hdd"
    Write-Output "       cni: $cni"
    Write-Output "    cninet: $cninet"
    Write-Output "   cniyaml: $cniyaml"
    Write-Output " dockercli: $dockercli"
  }
  ^print$ {
    Write-Output "***** $etchosts *****"
    get-content $etchosts | select-string -pattern '^#|^\s*$' -notmatch

    Write-Output "`n***** configured mac addresses *****`n"
    Write-Output $macs

    Write-Output "`n***** network interfaces *****`n"
    (get-vmswitch 'switch' -ea:silent | `
      format-list -property name, id, netadapterinterfacedescription | out-string).trim()

    if ($nettype -eq 'private') {
      Write-Output ''
      (get-netipaddress -interfacealias 'vEthernet (switch)' -ea:silent | `
        format-list -property ipaddress, interfacealias | out-string).trim()
      Write-Output ''
      (get-netnat 'natnet' -ea:silent | format-list -property name, internalipinterfaceaddressprefix | out-string).trim()
    }
  }
  ^net$ {
    switch ($nettype) {
      'private' { new-private-net -natnet $natnet -zwitch $zwitch -cblock $cidr }
      'public' { new-public-net -zwitch $zwitch -adapter $adapter }
    }
  }
  ^hosts$ {
    switch ($nettype) {
      'private' { update-etc-hosts -cblock $cidr }
      'public' { Write-Output "not supported for public net - use dhcp"  }
    }
  }
  ^macs$ {
    $cnt = 10
    0..$cnt | ForEach-Object {
      $comment = switch ($_) {0 {'master'} default {"node$_"}}
      $comma = if($_ -eq $cnt) { '' } else { ',' }
      Write-Output "  '$(new-mac-address)'$comma # $comment"
    }
  }
  ^image$ {
    new-vhdx-tmpl -imageurl $imageurl -srcimg $srcimg -vhdxtmpl $vhdxtmpl
  }
  ^master$ {
    new-machine -zwitch $zwitch -vmname 'master' -cpus $cpus `
      -mem $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) `
      -vhdxtmpl $vhdxtmpl -cblock $cidr -ip '10' -mac $macs[0]
  }
  '(^node(?<number>\d+)$)' {
    $num = [int]$matches.number
    $name = "node$($num)"
    new-machine -zwitch $zwitch -vmname $name -cpus 1 `
      -mem $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) `
      -vhdxtmpl $vhdxtmpl -cblock $cidr -ip "$($num + 10)" -mac $macs[$num]
  }
  ^write-iso-master$ {
    write-iso-file -zwitch $zwitch -vmname 'master' -cpus $cpus `
      -mem $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) `
      -vhdxtmpl $vhdxtmpl -cblock $cidr -ip '10' -mac $macs[0]
  }
  '(^write-iso-node(?<number>\d+)$)' {
    $num = [int]$matches.number
    $name = "node$($num)"
    write-iso-file -zwitch $zwitch -vmname $name -cpus 1 `
      -mem $(Invoke-Expression $ram) -hdd $(Invoke-Expression $hdd) `
      -vhdxtmpl $vhdxtmpl -cblock $cidr -ip "$($num + 10)" -mac $macs[$num]
  }
  ^info$ {
    get-our-vms
  }
  ^initialize-kubeadm$ {
    get-our-vms | ForEach-Object { wait-for-node-init -opts $sshopts -name $_.name }

    $init = "sudo kubeadm init --pod-network-cidr=$cninet --ignore-preflight-errors=NumCPU && \
      mkdir -p `$HOME/.kube && \
      sudo cp /etc/kubernetes/admin.conf `$HOME/.kube/config && \
      sudo chown `$(id -u):`$(id -g) `$HOME/.kube/config && \
      kubectl apply -f `$(eval echo $cniyaml)"

    Write-Output "executing on master: $init"

    ssh $sshopts $guestuser@master $init
    if (!$?) {
      Write-Output "master init has failed, aborting"
      exit 1
    }
  }
  ^invoke-kubeadm-join$ {
    if((get-our-vms | Where-Object { $_.name -match "node.+" }).count -eq 0) {
      Write-Output ""
      Write-Output "no worker nodes, removing NoSchedule taint from master..."
      ssh $sshopts $guestuser@master 'kubectl taint nodes master node-role.kubernetes.io/master:NoSchedule-'
      Write-Output ""
    }
    else {
      $joincmd = $(ssh $sshopts $guestuser@master 'sudo kubeadm token create --print-join-command')
      get-our-vms | Where-Object { $_.name -match "node.+" } |
        ForEach-Object {
          $node = $_.name
          Write-Output "`nexecuting on $node`: $joincmd"
          ssh $sshopts $guestuser@$node sudo $joincmd
          if (!$?) {
            Write-Output "$node init has failed, aborting"
            exit 1
          }
        }
    }
  }
  ^initialize-kubeconfig$ {
    initialize-kubeconfig
  }
  ^reboot$ {
    get-our-vms | ForEach-Object { $node = $_.name; $(ssh $sshopts $guestuser@$node 'sudo reboot') }
  }
  ^shutdown$ {
    get-our-vms | ForEach-Object { $node = $_.name; $(ssh $sshopts $guestuser@$node 'sudo shutdown -h now') }
  }
  ^save$ {
    get-our-vms | checkpoint-vm
  }
  ^restore$ {
    get-our-vms | foreach-object { $_ | get-vmsnapshot | Sort-Object creationtime | `
      Select-Object -last 1 | restore-vmsnapshot -confirm:$false }
  }
  ^stop$ {
    get-our-vms | stop-vm
  }
  ^start$ {
    get-our-vms | start-vm
  }
  ^delete$ {
    get-our-vms | ForEach-Object { remove-machine -name $_.name }
  }
  ^delnet$ {
    switch ($nettype) {
      'private' { remove-private-net -zwitch $zwitch -natnet $natnet }
      'public' { remove-public-net -zwitch $zwitch }
    }
  }
  ^time$ {
    Write-Output "local: $(Get-date)"
    get-our-vms | ForEach-Object {
      $node = $_.name
      Write-Output ---------------------$node
      # ssh $sshopts $guestuser@$node "date ; if which chronyc > /dev/null; then sudo chronyc makestep ; date; fi"
      ssh $sshopts $guestuser@$node "date"
    }
  }
  ^track$ {
    get-our-vms | ForEach-Object {
      $node = $_.name
      Write-Output ---------------------$node
      ssh $sshopts $guestuser@$node "date ; sudo chronyc tracking"
    }
  }
  ^docker$ {
    $saveto = "C:\ProgramData\chocolatey\bin\docker.exe"
    if (!(test-path $saveto)) {
      Write-Output "installing docker cli..."
      get-file -url $dockercli -saveto $saveto
    }
    Write-Output ""
    Write-Output "powershell:"
    Write-Output "  write-output '`$env:DOCKER_HOST = `"ssh://$guestuser@master`"' | out-file -encoding utf8 -append `$profile"
    Write-Output ""
    Write-Output "bash:"
    Write-Output "  write-output `"``nexport DOCKER_HOST='ssh://$guestuser@master'``n`" | out-file -encoding utf8 -append -nonewline ~\.profile"
    Write-Output ""
    Write-Output ""
    Write-Output "(restart your shell after applying the above)"
  }
  ^share$ {
    if (!( get-smbshare -name 'hyperctl' -ea silentlycontinue )) {
      Write-Output "creating host $HOME -> /hyperctl share..."
      new-smbshare -name 'hyperctl' -path $HOME
    }
    else {
      Write-Output "(not creating $HOME -> /hyperctl share, already present...)"
    }
    Write-Output ""

    $unc = convert-unc-path -path $HOME
    $cmd = "sudo mkdir -p $unc && sudo mount -t cifs //$cidr.1/hyperctl $unc -o sec=ntlm,username=$guestuser,vers=3.0,sec=ntlmv2,noperm"
    set-clipboard -value $cmd
    Write-Output $cmd
    Write-Output "  ^ copied to the clipboard, paste & execute on master:"
    Write-Output "    (just right-click (to paste), <enter your Windows password>, Enter, Ctrl+D)"
    Write-Output ""
    ssh $sshopts $guestuser@master

    Write-Output ""
    $unc = convert-unc-path -path $pwd.path
    $cmd = "docker run -it -v $unc`:$unc r-base ls -l $unc"
    set-clipboard -value $cmd
    Write-Output $cmd
    Write-Output "  ^ copied to the clipboard, paste & execute locally to test the sharing"
  }
  ^helm$ {
    install-helm
  }
  ^repo$ {
    # install openssl if none is provided
    # don't try to install one bc the install is intrusive and not fully automated
    $openssl = "openssl.exe"
    if(!(get-command "openssl" -ea silentlycontinue)) {
      # fall back to cygwin openssl if installed
      $openssl = "C:\tools\cygwin\bin\openssl.exe"
      if(!(test-path $openssl)) {
        Write-Output "error: please make sure 'openssl' command is in the path"
        Write-Output "(or install Cygwin so that '$openssl' exists)"
        Write-Output ""
        exit 1
      }
    }

    # add remote helm repo to you local ~/.helm registry
    hyperhelm repo add stable https://kubernetes-charts.storage.googleapis.com
    hyperhelm repo update

    # prepare secrets for local repo
    $certs="$workdir\certs"
    mkdir $certs -ea 0 | out-null
    $expr = "$openssl req -newkey rsa:4096 -nodes -sha256 " +
      "-subj `"/C=/ST=/L=/O=/CN=master`" -keyout $certs/tls.key -x509 " +
      "-days 365 -out $certs/tls.cert"
    invoke-expression $expr
    hyperctl create secret tls master --cert=$certs/tls.cert --key=$certs/tls.key

    # distribute certs to our nodes
    get-our-vms | ForEach-Object {
      $node = $_.name
      $(scp $sshopts $certs/tls.cert $guestuser@$node`:)
      $(ssh $sshopts $guestuser@$node 'sudo mkdir -p /etc/docker/certs.d/master:30699/')
      $(ssh $sshopts $guestuser@$node 'sudo mv tls.cert /etc/docker/certs.d/master:30699/ca.crt')
    }

    hyperhelm install registry stable/docker-registry `
      --set tolerations[0].key=node-role.kubernetes.io/master `
      --set tolerations[0].operator=Exists `
      --set tolerations[0].effect=NoSchedule `
      --set nodeSelector.kubernetes\.io/hostname=master `
      --set tlsSecretName=master `
      --set service.type=NodePort `
      --set service.nodePort=30699

    Write-Output ''
    show-local-repo-tips
    Write-Output ''
  }
  ^iso$ {
    write-yaml-contents -path "$($distro).yaml" -cblock $cidr
    Write-Output "debug cloud-config was written to .\${distro}.yaml"
  }
  default {
    Write-Output 'invalid command; try: .\hyperctl.ps1 help'
  }
}

Write-Output ''
