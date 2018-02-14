from amqplib import client_0_8 as amqp
import os
import json



#Rabbit
conn = amqp.Connection(host="{0}:5671".format(os.environ['RABBIT']), userid="guest",
password="guest", virtual_host="/", insist=False,ssl=True)

chan = conn.channel()

chan.queue_declare(queue="scanner", durable=True,
exclusive=False, auto_delete=False)
chan.exchange_declare(exchange="scanner", type="direct", durable=True,
auto_delete=False,)
chan.queue_bind(queue="scanner", exchange="scanner",
routing_key="#")



def add_to_que(message):
	'''
	Take message and add to que

	'''
	send = amqp.Message(message)
	print('add message to rabbitmq')
	chan.basic_publish(send,exchange="scanner",routing_key="#")
