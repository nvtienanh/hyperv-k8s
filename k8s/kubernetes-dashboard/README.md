```powershell
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.3.1/aio/deploy/recommended.yaml
kubectl apply -f https://raw.githubusercontent.com/nvtienanh/hyperv-k8s/main/k8s/kubernetes-dashboard/kubernetes-dashboard-service-np.yaml
kubectl -n kubernetes-dashboard describe secret $(kubectl -n kubernetes-dashboard get secret | Select-String admin-user )
kubectl -n kubernetes-dashboard describe secret admin-user-token-xkzqn
kubectl apply -f `$(eval echo $cniyaml)"
```

```powershell
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 30002 -Protocol TCP -InternalIPAddress "10.10.0.10" -InternalPort 30002 -NatName KubeNatNet
```