switch: switch.go 
	go mod tidy
	go build -o $@ $@.go
	# THIS IS VERY INSECURE !!!
	sudo chown root:root switch 
	sudo chmod +s switch 