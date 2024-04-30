#!/bin/bash

# Will only work for pods with either apt or ip installed, and will apt update those pods. 
kcp='sudo kubectl get pods' 
kce(){ 
        if [ -z $1 ]; then
                echo "Requires the name of pod to execute the shell in." 
                return 0; 
        fi; 

        sudo kubectl exec --stdin --tty "$1" -- ${2:-/bin/ash}
}


for i in $($kcp | cut -d" " -f 1 | tail -n +2); do kce $i 'apt update -y' &>/dev/null; kce $i 'apt install -y iproute2' &>/dev/null; echo "$i : $(kce $i 'ip a' | grep if | cut -d":" -f 2 | cut -d"@" -f 2 | sed 's/if//g')"; done

