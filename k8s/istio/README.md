# Download istio
```powershell
Invoke-WebRequest -Uri 'https://github.com/istio/istio/releases/download/1.11.1/istio-1.11.1-win.zip' -OutFile 'C:\istio.zip'
Expand-Archive -LiteralPath 'C:\istio.zip' -DestinationPath C:\
Remove-Item 'C:\istio.zip'
```

# Add to PATH
```powershell 
$oldPath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).Path
$newPath = "$oldPath;C:\istio-1.11.1\bin"  
Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")

istioctl install --set profile=demo -y
kubectl label namespace default istio-injection=enabled
kubectl get svc istio-ingressgateway -n istio-system
```

# Determining the ingress IP and ports

```powershell
$INGRESS_HOST = (kubectl -n istio-system get service istio-ingressgateway -o json | ConvertFrom-Json).status.loadBalancer.ingress[0].ip
$INGRESS_PORT = ((kubectl -n istio-system get service istio-ingressgateway -o json | ConvertFrom-Json).spec.ports | where {
 $_.name -eq "http2" }).port
$SECURE_INGRESS_PORT = ((kubectl -n istio-system get service istio-ingressgateway -o json | ConvertFrom-Json).spec.ports | where {
 $_.name -eq "https" }).port
```

# Install istio addons

```powershell
cd C:\istio-1.11.1
kubectl apply -f samples/addons
kubectl apply -f https://raw.githubusercontent.com/nvtienanh/hyperv-k8s/main/k8s/istio/istio-services-node-port.yaml
```

# NetNatStaticMapping

```powershell
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 32493 -Protocol TCP -InternalIPAddress "10.10.0.10" -InternalPort 32493 -NatName KubeNatNet
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 32494 -Protocol TCP -InternalIPAddress "10.10.0.10" -InternalPort 32494 -NatName KubeNatNet
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 32495 -Protocol TCP -InternalIPAddress "10.10.0.10" -InternalPort 32495 -NatName KubeNatNet
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 32496 -Protocol TCP -InternalIPAddress "10.10.0.10" -InternalPort 32496 -NatName KubeNatNet
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 80 -Protocol TCP -InternalIPAddress "10.10.0.200" -InternalPort 80 -NatName KubeNatNet
```

# Enable Firewall

```powershell
net stop nginx
Remove-NetFirewallRule -DisplayName "Allow HTTP and HTTPs over Nginx"
```

# Traffic Splitting Example

```powershell
Add-NetNatStaticMapping -ExternalIPAddress "0.0.0.0/24" -ExternalPort 80 -Protocol TCP -InternalIPAddress "10.10.0.200" -InternalPort 80 -NatName KubeNatNet
```

```powershell
kubectl create namespace example
kubectl label namespace example istio-injection=enabled
kubectl -n example apply -f https://raw.githubusercontent.com/nvtienanh/hyperv-k8s/main/k8s/istio/example/apple.yaml
kubectl -n example apply -f https://raw.githubusercontent.com/nvtienanh/hyperv-k8s/main/k8s/istio/example/banana.yaml
kubectl -n example apply -f https://raw.githubusercontent.com/nvtienanh/hyperv-k8s/main/k8s/istio/example/istio.yaml
```
