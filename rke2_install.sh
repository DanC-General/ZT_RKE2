#!/bin/bash
sudo apt install vim git curl python3 pip make python3.12-venv libpcap-dev tcpreplay 
sudo mkdir -p /etc/rancher/rke2
sudo cp ri-config.yaml /etc/rancher/rke2/config.yaml
sudo curl -sfL https://get.rke2.io | sudo sh -
sudo systemctl enable --now rke2-server.service 
sudo systemctl start rke2-server.service
echo 'KUBECONFIG="/etc/rancher/rke2/rke2.yaml"' | sudo tee -a /etc/environment
sudo cp /var/lib/rancher/rke2/bin/kubectl /usr/local/bin/kubectl
source /etc/environment 
cd module && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
echo "Reboot to persist changes." 
