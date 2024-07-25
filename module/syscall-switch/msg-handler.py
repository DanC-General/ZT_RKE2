import os
import pika
import json
import time
import subprocess
from datetime import datetime

prev_time = time.time()
class AMQPConnection:
    def __init__(self):
        credentials = pika.PlainCredentials("ztrke2", "ztrke2")
        parameters = pika.ConnectionParameters("localhost", 5673, "/", credentials)

        self.connection = pika.BlockingConnection(parameters)
        self.channel = self.connection.channel()

def on_recv(channel,method,properties,body): 
    global prev_time
    fields = json.loads(body.decode())
    # print(json.loads(body.decode()))
    try: 
        # print("Image: ", fields["output_fields"]["container.image.repository"], " pod name: ", fields["output_fields"]["k8s.pod.name"],fields["output_fields"]["container.name"],fields["rule"])
        if (fields["output_fields"]["container.name"] in fields["rule"]): 
            # print("Changing runtime...")
            # Don't need nanosecond precision
            time_s = str(int(float(fields["output_fields"]["evt.time"]) / 1000000000))
            # print(time_s)
            print("Container up for " , float(fields["output_fields"]["container.duration"])  / 1000000000 )
            # subprocess.run("./random_script.sh" + fields["output_fields"]["container.image.repository"] + " " + fields["output_fields"]["k8s.pod.name"] 
            #                + " " + time_s + " " + str(fields["output_fields"]["proc.pid"]),shell=True)
    except KeyError: 
        return 
    # print(f"DELAY (sent: {datetime.fromtimestamp(prev_time).strftime('%H:%M:%S')} received: {datetime.fromtimestamp(cur_time).strftime('%H:%M:%S')})\n {body.decode()}\n")


temp = AMQPConnection()
while(1):
    temp.channel.basic_consume(queue="events",on_message_callback=on_recv,auto_ack=True)
    temp.channel.start_consuming()
temp.connection.close()
