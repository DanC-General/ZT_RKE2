# ZT_RKE2
Repository of supporting code for Honours project. 

# Building 

## Install Docker 

[Here](https://docs.docker.com/engine/install/ubuntu/)

## Build images

`docker-compose -f up app/docker-compose.yaml`

## Install K8S 
Run rke2_install.sh

## Install kompose 
https://github.com/kubernetes/kompose

`curl -L https://github.com/kubernetes/kompose/releases/download/v1.33.0/kompose-linux-amd64 -o kompose`
`chmod +x kompose`
`sudo mv ./kompose /usr/local/bin/kompose`

Then need to fix errors on live - service names wrong 
Should just need to change '_' in Service names to '-' 

## Install libpcap libraries

`sudo apt-get install libpcap-dev` 

# Installation and Setup

Scripts have been provided that should automate the setup process. 

To run our testing environment, run the following commands:

`sudo ./rke2_install.sh`

Change into the app directory, and run the following: 

`./initialise_application.sh`

On a failure, instances in configuration files of our servers IP address (10.1.1.241) 
should be changed to reflect the desired server IP.

To activate the live system call monitoring, falco pods are required.
Change into the module/syscall-monitor directory and run the following: 

`./get_helm.sh`

`helm install falco --create-namespace -n falco -f falco.yaml falcosecurity/falco`

To ensure the setup has installed correctly, run the following command:

`kubectl get pods -A -o wide`

You should see three pods in the falco namespace, a collection of rke2 pods 
and the three application pods (ssh, http and mysql).

<!-- # Other installs  -->

<!-- Clean these -->
<!-- sudo apt install tcpreplay 
sudo apt install gnome-terminal -->

<!-- Maybe make sed script for this  -->
<!-- Change the deployment k8s/http-deployment hostPath field to use your username/ZT_RKE2 install location  -->

# Project Structure

```
.
├── app - Application Setup
│   ├── db - SQL database and endpoint 
│   ├── http - HTTP endpoint 
│   ├── k8s - Kubernetes configuration files
│   └── ssh - SSH endpoint
├── module - Main ZT_RKE2 code 
│   ├── Kit_Agent - Kitsune source code + online FE
│   ├── logs - Logs for system activation
│   ├── policy - Generates system call profiles
│   ├── scripts - Assorted scripts
│   ├── syscall-monitor - Live syscall monitoring
│   └── venv
├── performance - Analysis/comparison files
│   ├── example_files - Some example python for analysis
│   ├── resource_util - Resource utilisation performance tools
│   └── Trial_Out - Trial examples
└── traffic
    └── vm_automation - Scripts for SSH traffic generation 
```