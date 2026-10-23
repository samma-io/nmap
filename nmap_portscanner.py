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
from sammaParser import logger, endThis
from target_check import require_valid_target


def nmap_command(target):
	'''
	Build the nmap argv list. The target is one argument of its own, so
	nothing in it is interpreted by a shell. sudo stays because the image
	runs as the samma user with a sudoers rule for /bin/nmap, and -sS needs
	raw sockets.
	'''
	return ['sudo', '/bin/nmap', '-sS', '-oX', '/out/result.xml', target]


def start_scan(target):
	'''
	Start the nmap scan of the target
	'''
	subprocess.run(nmap_command(target), stdout=subprocess.DEVNULL, check=False)



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


if __name__ == '__main__':
	#Refuse a bad target before anything runs, then scan and get the output
	target = require_valid_target()
	start_scan(target)
	convert_output()
	endThis()
