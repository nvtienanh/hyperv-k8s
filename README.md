# hyperv-k8s
PowerShell script to deploy Kubernetes cluster on Microsoft Hyper-V Server

# Commands

- `Install-Tools`: Install packages kubectl, docker, qemu-img
- `Show-Config`: show script config vars
- `Deploy-Network`: install private or public host network
- `Deploy-HostsFile`: append private network node names to etc/hosts
- `Get-Image`: download the VM image
- `Deploy-Master`: create and launch master node
- `Deploy-NodeN`: create and launch worker node (node1, node2, ...)
- `Save-ISOMaster`: save master node
- `Save-ISONodeN`: save worker node (node1, node2, ...)
- `Get-Info`: display info about nodes
- `Initialize-Kubeadm`: Initialize kubeadm
- `Start-KubeadmJoin`: Run Kubeadm joind command
- `Save-KubeConfig`: Save Kube config to host
- `Restart-K8sVM`: Soft-reboot the nodes
- `Invoke-Shutdown`: Soft-shutdown the nodes
- `Save-K8sVM`: Snapshot the VMs
- `Restore-K8sVM`: Restore VMs from latest snapshots
- `Stop-K8sVM`: Stop the VMs
- `Start-K8sVM`: Start the VMs
- `Remove-K8sVM`: Stop VMs and delete the VM files
- `Remove-Network`: Delete the network

# Refereces
- https://github.com/youurayy/hyperctl