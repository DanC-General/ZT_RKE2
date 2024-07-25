FILES=(test)

test: test.go
	go mod tidy
	go build -o $@ $@.go
	# THIS IS VERY INSECURE !!!
	sudo chown root:root test 
	sudo chmod +s test 
