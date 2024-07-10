#!/bin/bash
sudo mkdir -p /etc/rancher/rke2
sudo cp ri-config.yaml /etc/rancher/rke2/config.yaml
sudo curl -sfL https://get.rke2.io | sudo sh -
sudo systemctl enable --now rke2-server.service 
sudo systemctl start rke2-server.service
echo 'KUBECONFIG="/etc/rancher/rke2/rke2.yaml"' | sudo tee -a /etc/environment
source /etc/environment 
