import pika

class AMQPConnection:
    def __init__(self):
        credentials = pika.PlainCredentials("ztrke2", "ztrke2")
        parameters = pika.ConnectionParameters("localhost", 5673, "/", credentials)
        self.connection = pika.BlockingConnection(parameters)
        self.channel = self.connection.channel()

temp = AMQPConnection()
temp.channel.queue_declare(queue='events')
