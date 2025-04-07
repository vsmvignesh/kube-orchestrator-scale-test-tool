#!/bin/bash

# Function to display usage
usage() {
  echo "Usage: $0 --resource-group-name <name> --rancher-hostname <hostname>"
  echo ""
  echo "Required arguments:"
  echo "  -r, --resource-group-name   Resource group name for Azure (e.g., myResourceGroup)"
  echo "  -h, --rancher-hostname      Rancher hostname to be set (e.g., rancher.example.com)"
  echo ""
  echo "Optional arguments:"
  echo "  --help                      Display this help message"
  exit 0
}

# Parse command-line arguments
while [[ "$#" -gt 0 ]]; do
  case $1 in
    -r|--resource-group-name)
      RESOURCE_GROUP="$2"
      shift 2
      ;;
    -h|--rancher-hostname)
      RANCHER_HOSTNAME="$2"
      shift 2
      ;;
    --help)
      usage
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      ;;
  esac
done

# Check if resource group name and Rancher hostname are provided
if [ -z "$RESOURCE_GROUP" ] || [ -z "$RANCHER_HOSTNAME" ]; then
  echo "Error: Both resource group name and Rancher hostname are required."
  usage
fi

# Variables derived from resource group name
LOCATION="eastus2"
VNET_NAME="${RESOURCE_GROUP}Vnet"
SUBNET_NAME="${RESOURCE_GROUP}Subnet"
NSG_NAME="${RESOURCE_GROUP}NSG"
LB_NAME="${RESOURCE_GROUP}LoadBalancer"
MYSQL_SERVER="${RESOURCE_GROUP}mysql"
MYSQL_ADMIN_USER="myadmin"
MYSQL_ADMIN_PASSWORD="password1"  # Replace with a secure password in production
PUBLIC_IP1="${RESOURCE_GROUP}PublicIP1"
PUBLIC_IP2="${RESOURCE_GROUP}PublicIP2"
PUBLIC_IP3="${RESOURCE_GROUP}PublicIP3"
LB_PUBLIC_IP="${RESOURCE_GROUP}LBPublicIP"
NIC1="${RESOURCE_GROUP}NIC1"
NIC2="${RESOURCE_GROUP}NIC2"
VM1="${RESOURCE_GROUP}Node1"
VM2="${RESOURCE_GROUP}Node2"
admin_username="ubuntu"

# Function to check command success
check_status() {
  if [ $? -ne 0 ]; then
    echo "Error: $1 failed. Exiting."
    exit 1
  fi
}

# Display configuration
echo "Resource Group: $RESOURCE_GROUP"
echo "Rancher will be installed with hostname: $RANCHER_HOSTNAME"

# Step 1: Create Azure Resource Group
echo "Creating resource group: $RESOURCE_GROUP..."
az group create -l "$LOCATION" -n "$RESOURCE_GROUP"
check_status "Resource group creation"

# The rest of your script continues below...

# Step 2: Set default location and resource group
echo "Setting defaults..."
az configure --defaults location="$LOCATION" group="$RESOURCE_GROUP"
check_status "Setting defaults"

# Step 3: Create virtual network, public IPs, and network security group
echo "Creating virtual network and subnet: $VNET_NAME..."
az network vnet create --name "$VNET_NAME" --subnet-name "$SUBNET_NAME"
check_status "VNet creation"

echo "Creating public IPs..."
az network public-ip create --name "$PUBLIC_IP1" --sku standard
az network public-ip create --name "$PUBLIC_IP2" --sku standard
az network public-ip create --name "$PUBLIC_IP3" --sku standard
check_status "Public IP creation"

echo "Creating network security group: $NSG_NAME..."
az network nsg create --name "$NSG_NAME"
check_status "NSG creation"

echo "Creating NSG rule for SSH..."
az network nsg rule create --nsg-name "$NSG_NAME" -n "${RESOURCE_GROUP}NsgRuleSSH" \
  --priority 100 --source-address-prefixes '*' --source-port-ranges '*' \
  --destination-address-prefixes '*' --destination-port-ranges 22 \
  --access Allow --protocol Tcp --description "Allow SSH Access to all VMs"
check_status "NSG SSH rule creation"

# Step 4: Create public IP and load balancer configuration
echo "Creating public IP for load balancer: $LB_PUBLIC_IP..."
az network public-ip create --name "$LB_PUBLIC_IP" --sku standard
check_status "LB public IP creation"

echo "Creating load balancer: $LB_NAME..."
az network lb create --name "$LB_NAME" --public-ip-address "$LB_PUBLIC_IP" \
  --frontend-ip-name "${RESOURCE_GROUP}FrontEnd" --backend-pool-name "${RESOURCE_GROUP}BackEndPool" \
  --sku standard
check_status "Load balancer creation"

echo "Creating load balancer probe..."
az network lb probe create --lb-name "$LB_NAME" --name "${RESOURCE_GROUP}HealthProbe" \
  --protocol tcp --port 80
check_status "LB probe creation"

echo "Fetching Load Balancer Public IP..."
LB_IP=$(az network public-ip show --name "$LB_PUBLIC_IP" --resource-group "$RESOURCE_GROUP" --query ipAddress --output tsv)
check_status "Fetching Load Balancer Public IP"
echo "Load Balancer Public IP: $LB_IP"

# Step 5: Access policies
echo "Creating NSG rule for HTTP/HTTPS/K3s ports..."
az network nsg rule create --nsg-name "$NSG_NAME" -n "${RESOURCE_GROUP}NSGRuleHTTP" \
  --protocol tcp --direction inbound --source-address-prefix '*' --source-port-range '*' \
  --destination-address-prefixes '*' --destination-port-range 80 443 6443 \
  --access allow --priority 200
check_status "NSG HTTP rule creation"

echo "Creating LB rules..."
az network lb rule create --lb-name "$LB_NAME" -n "${RESOURCE_GROUP}HTTPRule" \
  --protocol tcp --frontend-port 80 --backend-port 80 \
  --frontend-ip-name "${RESOURCE_GROUP}FrontEnd" --backend-pool-name "${RESOURCE_GROUP}BackEndPool" \
  --probe-name "${RESOURCE_GROUP}HealthProbe"
az network lb rule create --lb-name "$LB_NAME" -n "${RESOURCE_GROUP}HTTPSRule" \
  --protocol tcp --frontend-port 443 --backend-port 443 \
  --frontend-ip-name "${RESOURCE_GROUP}FrontEnd" --backend-pool-name "${RESOURCE_GROUP}BackEndPool" \
  --probe-name "${RESOURCE_GROUP}HealthProbe"
az network lb rule create --lb-name "$LB_NAME" -n "${RESOURCE_GROUP}HTTPS6443Rule" \
  --protocol tcp --frontend-port 6443 --backend-port 6443 \
  --frontend-ip-name "${RESOURCE_GROUP}FrontEnd" --backend-pool-name "${RESOURCE_GROUP}BackEndPool" \
  --probe-name "${RESOURCE_GROUP}HealthProbe"
check_status "LB rules creation"

# Step 6: Create MySQL server with auto-yes
echo "Creating MySQL server: $MYSQL_SERVER..."
az mysql flexible-server create --name "$MYSQL_SERVER" \
  --admin-user "$MYSQL_ADMIN_USER" --admin-password "$MYSQL_ADMIN_PASSWORD" \
  --version 5.7 --yes
check_status "MySQL server creation"

echo "Creating MySQL firewall rule..."
az mysql flexible-server firewall-rule create --rule-name "AllowallAzureIPS" \
  --resource-group "$RESOURCE_GROUP" --name "$MYSQL_SERVER" \
  --start-ip-address 0.0.0.0 --end-ip-address 0.0.0.0
check_status "MySQL firewall rule creation"

echo "Turning off MySQL SSL security..."
az mysql flexible-server parameter set --name require_secure_transport \
  --resource-group "$RESOURCE_GROUP" --server-name "$MYSQL_SERVER" --value OFF
check_status "Turning off MySQL SSL security"

echo "Initializing MySQL database and capturing output..."
MYSQL_OUTPUT=$(mysql --host "$MYSQL_SERVER.mysql.database.azure.com" \
  --user "$MYSQL_ADMIN_USER" --password="$MYSQL_ADMIN_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS kubernetes;
SHOW DATABASES;
status;
EOF
)
check_status "MySQL database initialization"

echo "MySQL commands output for reference:"
echo "---------------------------------------"
echo "$MYSQL_OUTPUT"
echo "---------------------------------------"

# Step 7: Create NICs
echo "Creating network interfaces..."
az network nic create --name "$NIC1" --vnet-name "$VNET_NAME" --subnet "$SUBNET_NAME" \
  --network-security-group "$NSG_NAME" --public-ip-address "$PUBLIC_IP1" \
  --lb-name "$LB_NAME" --lb-address-pools "${RESOURCE_GROUP}BackEndPool"
az network nic create --name "$NIC2" --vnet-name "$VNET_NAME" --subnet "$SUBNET_NAME" \
  --network-security-group "$NSG_NAME" --public-ip-address "$PUBLIC_IP2" \
  --lb-name "$LB_NAME" --lb-address-pools "${RESOURCE_GROUP}BackEndPool"
check_status "NIC creation"

# Step 8: Create first VM with K3s server using provided cloud-init
echo "Creating cloud-init file for $VM1..."
cat <<EOF > cloud-init.txt
#cloud-config
package_upgrade: true
ppackages:
  - curl
  - apt-transport-https
  - ca-certificates
  - gnupg
output: {all: '| tee -a /var/log/cloud-init-output.log'}
runcmd:
  - curl https://releases.rancher.com/install-docker/18.09.sh | sh
  - sudo usermod -aG docker ubuntu
  - curl -sfL https://get.k3s.io | sh -s - server --datastore-endpoint="mysql://$MYSQL_ADMIN_USER:$MYSQL_ADMIN_PASSWORD@tcp($MYSQL_SERVER.mysql.database.azure.com:3306)/kubernetes"
  - curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
  - chmod +x get_helm.sh
  - ./get_helm.sh --version $helm_version
EOF

echo "Creating VM: $VM1..."
az vm create --name "$VM1" --image "Ubuntu2404" --nics "$NIC1" \
  --admin-username "ubuntu" --generate-ssh-keys --custom-data cloud-init.txt
check_status "$VM1 creation"

# Fetch VM1 public IP
echo "Fetching public IP for $VM1..."
FIRST_VM_IP=$(az network public-ip show --resource-group "$RESOURCE_GROUP" --name "$PUBLIC_IP1" --query ipAddress --output tsv)
check_status "Fetching $VM1 public IP"
echo "$VM1 Public IP: $FIRST_VM_IP"

# Wait for VM to be fully provisioned (cloud-init might take a moment)
echo "Waiting 120 seconds for $VM1 to finish provisioning..."
sleep 120


# Verify cloud-init execution and K3s setup on VM1 via SSH
echo "Verifying cloud-init execution on $VM1..."
CLOUD_INIT_LOG=$(ssh -o "StrictHostKeyChecking=no" "$admin_username@$FIRST_VM_IP" "sudo cat /var/log/cloud-init-output.log")
DOCKER_VERSION=$(ssh -o "StrictHostKeyChecking=no" "$admin_username@$FIRST_VM_IP" "docker --version")
K3S_STATUS=$(ssh -o "StrictHostKeyChecking=no" "$admin_username@$FIRST_VM_IP" "sudo systemctl status k3s")

echo "Cloud-init output from $VM1:"
echo "---------------------------------------"
echo "$CLOUD_INIT_LOG"
echo "---------------------------------------"

echo "Docker version on $VM1:"
echo "---------------------------------------"
echo "$DOCKER_VERSION"
echo "---------------------------------------"

echo "K3s status on $VM1:"
echo "---------------------------------------"
echo "$K3S_STATUS"
echo "---------------------------------------"

# Check if K3s is active
if echo "$K3S_STATUS" | grep -q "active (running)"; then
  echo "K3s is running successfully on $VM1."
else
  echo "Error: K3s is not running on $VM1. Please check the logs."
  exit 1
fi

# Fetch K3s node token from VM1
echo "Retrieving K3s node token from $VM1..."
NODE_TOKEN=$(ssh -o "StrictHostKeyChecking=no" "$admin_username@$FIRST_VM_IP" "sudo cat /var/lib/rancher/k3s/server/node-token")
check_status "Fetching K3s node token"
echo "K3s Node Token: $NODE_TOKEN"


# Step 9: Create second VM with K3s server
echo "Creating cloud-init file for $VM2..."
cat <<EOF > cloud-init.txt
#cloud-config
package_upgrade: true
packages:
  - curl
output: {all: '| tee -a /var/log/cloud-init-output.log'}
runcmd:
  - curl https://releases.rancher.com/install-docker/18.09.sh | sh
  - sudo usermod -aG docker ubuntu
  - curl -sfL https://get.k3s.io | K3S_URL=https://$FIRST_VM_IP:6443 K3S_TOKEN=$NODE_TOKEN sh -s - server --datastore-endpoint="mysql://$MYSQL_ADMIN_USER:$MYSQL_ADMIN_PASSWORD@tcp($MYSQL_SERVER.mysql.database.azure.com:3306)/kubernetes"
EOF

echo "Creating VM: $VM2..."
az vm create --name "$VM2" --image "Ubuntu2404" --nics "$NIC2" \
  --admin-username "ubuntu" --generate-ssh-keys --custom-data cloud-init.txt
check_status "$VM2 creation"

# Step 10: Install Rancher with conditional hostname flag
# Install Rancher on VM1 via SSH
echo "Installing Rancher on $VM1..."
if [ "$USE_HOSTNAME" = "yes" ]; then
  ssh -o "StrictHostKeyChecking=no" "$admin_username@$FIRST_VM_IP" <<EOF
helm repo add rancher-latest https://releases.rancher.com/server-charts/latest
kubectl create namespace cattle-system
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set crds.enabled=true
kubectl get pods --namespace cert-manager
helm install rancher rancher-latest/rancher --namespace cattle-system --set hostname=$RANCHER_HOSTNAME --set bootstrapPassword=admin
EOF
else
  ssh -o "StrictHostKeyChecking=no" "$admin_username@$FIRST_VM_IP" <<EOF
helm repo add rancher-latest https://releases.rancher.com/server-charts/latest
kubectl create namespace cattle-system
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager --namespace cert-manager --create-namespace --set crds.enabled=true
kubectl get pods --namespace cert-manager
helm install rancher rancher-latest/rancher --namespace cattle-system --set bootstrapPassword=admin
EOF
fi
check_status "Rancher installation on $VM1"

# Step 11: Final instructions
if [ "$USE_HOSTNAME" = "yes" ]; then
  echo "Add the following to /etc/hosts on your local machine:"
  echo "$LB_IP  $RANCHER_HOSTNAME"
  echo "Access Rancher at: https://$RANCHER_HOSTNAME (ignore self-signed cert warning for development)."
else
  echo "Rancher installed without a hostname. Access it via the load balancer IP: https://$LB_IP (ignore self-signed cert warning for development)."
fi

echo "Script completed successfully!"

