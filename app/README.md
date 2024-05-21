## DB SETUP 

install mysql-server or client on the connecting machine 
Need to connect to container with either protocol=tcp or -h 127.0.0.1 : 'localhost' will not work
`mysql -h 127.0.0.1 -u root -ppassword_123!`

## SSH 
https://satvikakolisetty.medium.com/running-ssh-server-in-a-docker-container-55eb2a3add35

### Using 

To log in to the SSH container, run 

`ssh <user>@localhost -p 8003` 
 
Then enter your password when prompted. 

For example, to login as root: 

`ssh root@localhost -p 8003` 
`root@localhost's password: test`

## Registry 
https://wuestkamp.medium.com/setting-up-a-local-docker-container-registry-845b3e4e8aeb

## HTTP
Got the source code originally from this page: 
https://github.com/anveshmuppeda/docker-login-page/tree/main

Removed unnecessary files, change to work with running sql database. 
Will push to own image and put on own network. 
