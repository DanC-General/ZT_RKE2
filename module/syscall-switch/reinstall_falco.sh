#/bin/bash
helm uninstall falco -n falco && helm install falco -n falco -f falco.yaml falcosecurity/falco
helm install falco -n falco -f falco.yaml falcosecurity/falco
# start image - need to make events queue
docker run -it --rm --name rabbitmq -p 5673:5672 -p 15673:15672 -e RABBITMQ_DEFAULT_USER=ztrke2 -e RABBITMQ_DEFAULT_PASS=ztkre2 rabbitmq:3.12-management
