https://github.com/leostratus/netinet/blob/master/tcp.h
https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip.h.html
https://sites.uclouvain.be/SystInfo/usr/include/net/ethernet.h.html
https://www.winpcap.org/docs/docs_41/html/structpcap__pkthdr.html

Also need to install falco and inspektor gadget 

Install krew > install gadget > install helm > install falco 
https://krew.sigs.k8s.io/docs/user-guide/setup/install/
```(
  set -x; cd "$(mktemp -d)" &&
  OS="$(uname | tr '[:upper:]' '[:lower:]')" &&
  ARCH="$(uname -m | sed -e 's/x86_64/amd64/' -e 's/\(arm\)\(64\)\?.*/\1\2/' -e 's/aarch64$/arm64/')" &&
  KREW="krew-${OS}_${ARCH}" &&
  curl -fsSLO "https://github.com/kubernetes-sigs/krew/releases/latest/download/${KREW}.tar.gz" &&
  tar zxvf "${KREW}.tar.gz" &&
  ./"${KREW}" install krew
)
```
Add to bashrc 
    export PATH="${KREW_ROOT:-$HOME/.krew}/bin:$PATH"
Restart shell 
    source ~/.bashrc
Be careful of running this as root - sudo won't have access to same env

https://krew.sigs.k8s.io/docs/user-guide/quickstart/
https://www.inspektor-gadget.io/docs/latest/getting-started/install-kubernetes/
kubectl gadget deploy 
Edit falco docs and replace with ip of running node for rabbitmq image host

Helm install 

curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh