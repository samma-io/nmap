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
from nmap_args import port_scan_command


def nmap_command(target):
	'''
	The nmap argv list, built by nmap_args. By default nmap runs through
	sudo as a SYN scan (-sS), which needs raw sockets; with
	NMAP_UNPRIVILEGED=1 it runs without sudo as a connect scan (-sT). The
	target is one argument of its own, so nothing in it is interpreted by a
	shell.
	'''
	return port_scan_command(target)


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
