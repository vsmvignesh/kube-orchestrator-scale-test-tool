#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "🚀 Starting dependency installation for AKS, vCluster, and Rancher integration..."

# Parse command-line arguments
while getopts "a:p:t:" opt; do
  case $opt in
    a) app_id="$OPTARG" ;;
    p) app_password="$OPTARG" ;;
    t) tenant_id="$OPTARG" ;;
    \?) echo "❌ Invalid option -$OPTARG" >&2; exit 1 ;;
  esac
done

# Check if all required arguments are provided
if [[ -z "$app_id" || -z "$app_password" || -z "$tenant_id" ]]; then
    echo "❌ Missing required arguments!"
    echo "Usage: $0 -a <app_id> -p <app_password> -t <tenant_id>"
    exit 1
fi

# Ensure system packages are updated
echo "🔄 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install required system dependencies
echo "🔧 Installing required CLI tools..."
sudo apt install -y curl wget unzip ca-certificates lsb-release apt-transport-https gnupg jq software-properties-common

# Install Azure CLI
echo "🔧 Installing Azure CLI..."
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Install Kubernetes CLI tools (kubectl)
echo "🔧 Installing Kubernetes CLI tools..."
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list
sudo apt update
sudo apt install -y kubectl

# Install container runtime (containerd)
echo "🔧 Installing container runtime (containerd)..."
sudo apt install -y containerd
sudo mkdir -p /etc/containerd
sudo containerd config default | sudo tee /etc/containerd/config.toml > /dev/null
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl restart containerd

# Enable kubectl auto-completion
echo "⚙️ Enabling kubectl shell completion..."
echo 'source <(kubectl completion bash)' >> ~/.bashrc
source ~/.bashrc

# Install Helm
echo "🔧 Installing Helm..."
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Install kubelogin
echo "🔧 Installing kubelogin..."
curl -LO https://github.com/Azure/kubelogin/releases/latest/download/kubelogin-linux-amd64.zip
unzip kubelogin-linux-amd64.zip
sudo mv bin/linux_amd64/kubelogin /usr/local/bin/
rm kubelogin-linux-amd64.zip
sudo az aks install-cli

# Install Python 3.9
echo "🐍 Installing Python 3.9..."
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.9 python3.9-venv python3.9-dev python3.9-distutils

# Set Python 3.9 as default
echo "⚙️ Setting Python 3.9 as default..."
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.9 1
sudo update-alternatives --set python3 /usr/bin/python3.9

# Install pip for Python 3.9
echo "📦 Installing pip for Python 3.9..."
sudo apt remove python3-pip -y
curl -sS https://bootstrap.pypa.io/get-pip.py | python3.9

# Create a virtual environment
echo "🐍 Creating a virtual environment using Python 3.9..."
python3.9 -m venv ~/.venv
source ~/.venv/bin/activate

# Install k3d
sudo apt install docker.iocurl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh | bash

# Upgrade pip and install required Python packages
echo "📦 Installing Python dependencies..."
pip install --upgrade pip setuptools wheel
pip install azure-identity azure-mgmt-containerservice azure-mgmt-resource kubernetes dotmap tenacity filelock azure-mgmt-network azure-mgmt-privatedns tqdm

# Authenticate with Azure
echo "🔐 Logging in to Azure..."
az login --service-principal -u "$app_id" -p "$app_password" --tenant "$tenant_id"
echo "⚡ Please ensure you select the correct subscription!"

# Check available AKS versions
echo "🔍 Checking available AKS versions in East US..."
az aks get-versions --location eastus -o table

# Set up Helm repository for vCluster
echo "🔄 Adding Helm repository for vCluster..."
helm repo add loft-sh https://charts.loft.sh
helm repo update

# Install vcluster based on system architecture
echo "🔧 Detecting system architecture..."
ARCH=$(uname -m)

if [[ "$ARCH" == "x86_64" ]]; then
    VCLUSTER_ARCH="amd64"
elif [[ "$ARCH" == "aarch64" || "$ARCH" == "arm64" ]]; then
    VCLUSTER_ARCH="arm64"
else
    echo "❌ Unsupported architecture: $ARCH"
    exit 1
fi

echo "🔧 Installing vcluster for $VCLUSTER_ARCH..."
curl -L "https://github.com/loft-sh/vcluster/releases/latest/download/vcluster-linux-$VCLUSTER_ARCH" -o vcluster

# Activate virtual environment
source ~/.venv/bin/activate

# Make it executable and move to /usr/local/bin
sudo chmod +x vcluster
sudo mv vcluster /usr/local/bin

echo "✅ vcluster installed successfully!"

# Check installations
echo "✅ Verifying installations..."
python3 --version
pip --version
kubectl version --client
helm version
az version
vcluster --version

echo "🎉 All dependencies installed successfully with Python 3.9 and Kubernetes!"
