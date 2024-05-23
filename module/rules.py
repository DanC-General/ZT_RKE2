import os
import time

pipe = "traffic_data"

while not os.path.exists(pipe):
    pass  # Wait for the named pipe to be created

with open(pipe, 'r') as f: 
    # while True: 
    print("looping ")
    while True: 
        data = f.readline()
        print(data)
    

os.unlink(pipe)  # Delete named pipe (optional)
