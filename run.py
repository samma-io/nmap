# -*- coding: utf-8 -*-
##
##
#
# Start the nmap scan and wait for it to complete.
# Then format the resonse and send the data back to the server
#
import subprocess
import os
import xmltodict, json
from rabbitmq import add_to_que




def start_scan():
	'''
	Start the nmap scan of the target
	'''
	print('Start the nmap scan')
	process = subprocess.Popen('nmap -sS -oX result.xml {0} '.format(os.environ['TARGET']) , shell=True, stdout=subprocess.PIPE)
	process.wait()



def convert_output():
	'''
	Converts the output to json
	'''
	f = open("result.xml","r") 
	text = f.read()
	o = xmltodict.parse(text)


	try:
		for port in o['nmaprun']['host']['ports']['port']:
			print json.dumps(port)
			o['nmaprun']['host']['ports']['port']=port
			json_out = json.dumps(o)
			print json_out
			add_to_que(str(json_out))



	except KeyError:
		json_out = json.dumps(o)
		print json_out
start_scan()
convert_output()