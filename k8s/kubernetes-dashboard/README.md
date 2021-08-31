# Deploy Kubernetes Dashboard

```powershell
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.3.1/aio/deploy/recommended.yaml
```

# Create NodePort server to access dashboard

```powershell
kubectl apply -f https://raw.githubusercontent.com/nvtienanh/hyperv-k8s/main/k8s/kubernetes-dashboard/kubernetes-dashboard-service-np.yaml
```

# NetNatStaticMapping

```powershell
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 30002 -Protocol TCP -InternalIPAddress "10.10.0.10" -InternalPort 30002 -NatName KubeNatNet
```

# Get token to access dashboard

```powershell
$account = ((kubectl -n kubernetes-dashboard get secret -o json | ConvertFrom-Json).items.metadata | where {
 $_.annotations.'kubernetes.io/service-account.name' -eq "admin-user" }).name
kubectl -n kubernetes-dashboard describe secret $account
```