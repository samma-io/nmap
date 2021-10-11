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
from sammaParser import logger




def start_scan():
	'''
	Start the nmap scan of the target
	'''
	process = subprocess.Popen('sudo /bin/nmap -sS -oX /out/result.xml {0} '.format(os.environ['TARGET']) , shell=True, stdout=subprocess.PIPE)
	process.wait()



def convert_output():
	'''
	Converts the output to json
	'''
	f = open("/out/result.xml","r") 
	text = f.read()
	o = xmltodict.parse(text)
	json_data = json.dumps(o)

	try:
		for host in o['nmaprun']['host']['ports']['port']:
			out_json ={}
			out_json['type'] ="nmap"
			out_json['scanner'] ="nmap_port"
			out_json["target"]="{0}".format(os.environ['TARGET'])
			out_json['port']= host['@portid']
			out_json['protocol']=host['@protocol']
			#out_json["runstats"]= o['nmaprun']['runstats']
			logger(out_json)





	except KeyError:
		json_out = json.dumps(o)
		#print(json_out)
start_scan()
convert_output()