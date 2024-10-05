#/bin/bash
# For the installation of Falco, the eBPF tool necessary for system call analysis.
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install --replace falco --namespace falco --create-namespace --set tty=true falcosecurity/falco
helm uninstall falco -n falco && helm install falco -n falco -f falco.yaml falcosecurity/falco
helm install falco --create-namespace -n falco -f falco.yaml falcosecurity/falco
# start image - need to make events queue
docker run -it --rm --name rabbitmq -p 5673:5672 -p 15673:15672 -e RABBITMQ_DEFAULT_USER=ztrke2 -e RABBITMQ_DEFAULT_PASS=ztrke2 rabbitmq:3.12-management
