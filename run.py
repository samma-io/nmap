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
	json_out = json.dumps(o)
	print json_out
start_scan()
convert_output()
