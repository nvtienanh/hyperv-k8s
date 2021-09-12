# On windows client

- Create ssh pubic key for Windows client
- Download ssh public key of Hyper-V server
- Create file `$HOME\Documents\ssh-key.pub` then paste 2 ssh key.
- Run powershell as admin and change working dir to the folder contain `hyperv-nfs.ps1` scripts


```powershell
.\hyperv-nfs.ps1 Get-Image
.\hyperv-nfs.ps1 Save-ISONFS1
```

# On Windows Admin Center

- Upload iso file, `ssh-key.pub` and `hyperv-nfs.ps1` to server
- Open Powershell

```powershell
.\hyperv-nfs.ps1 Get-Image
.\hyperv-nfs.ps1 Deploy-HostsFile
.\hyperv-nfs.ps1 Deploy-ISONFS1
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 2222 -Protocol TCP -InternalIPAddress "10.10.0.101" -InternalPort 22 -NatName KubeNatNet
```

# Video tutorial

- [Microsoft Hyper-V Server: Create a NFS Server](https://www.youtube.com/watch?v=gIdUB1cbAkg)
