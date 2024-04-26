#!/bin/bash
sudo curl -sfL https://get.rke2.io | sudo sh -
sudo systemctl enable --now rke2-server.service 
echo 'KUBECONFIG=/etc/rancher/rke2/rke2.yaml' sudo >> /etc/environment
source /etc/environment 
