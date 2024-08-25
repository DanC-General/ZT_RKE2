#!/bin/bash
sudo rm -rf /mnt/virtiofs/new_traffic /mnt/virtiofs2/vm_automation
sudo cp -r /home/dc/ZT_RKE2/traffic/vm_automation /mnt/virtiofs/
sudo cp -r /home/dc/ZT_RKE2/traffic/vm_automation /mnt/virtiofs2/ 
