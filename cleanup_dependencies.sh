#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "🧹 Starting cleanup of dependencies..."

# Uninstall Python packages
echo "📦 Removing Python dependencies..."
pip uninstall -y azure-identity azure-mgmt-containerservice azure-mgmt-resource rancher-client kubernetes

# Remove Python 3.9
echo "🐍 Removing Python 3.9..."
sudo apt remove --purge -y python3.9 python3.9-dev python3.9-distutils python3.9-venv
sudo apt autoremove -y
sudo add-apt-repository --remove -y ppa:deadsnakes/ppa

# Remove Azure CLI
echo "🔧 Removing Azure CLI..."
sudo apt remove --purge -y azure-cli
sudo rm -rf /usr/lib/azure-cli /usr/local/bin/az

# Remove kubectl
echo "🔧 Removing kubectl..."
sudo rm -f /usr/local/bin/kubectl

# Remove Helm
echo "🔧 Removing Helm..."
sudo rm -f /usr/local/bin/helm

# Remove kubelogin
echo "🔧 Removing kubelogin..."
sudo rm -f /usr/local/bin/kubelogin

# Clean up system packages
echo "🧹 Cleaning up unused packages..."
sudo apt autoremove -y
sudo apt clean

# Verify removal
echo "✅ Verifying cleanup..."
command -v python3 || echo "Python3 removed"
command -v pip || echo "Pip removed"
command -v kubectl || echo "kubectl removed"
command -v helm || echo "Helm removed"
command -v az || echo "Azure CLI removed"

echo "🎉 Cleanup completed!"
