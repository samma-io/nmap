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
from nmap_args import http_recon_command


def nmap_command(target):
	'''
	The nmap argv list, built by nmap_args. By default nmap runs through
	sudo; with NMAP_UNPRIVILEGED=1 it runs without sudo. Version detection
	and the http-enum script need no raw sockets, so the flags are the same
	in both modes. The target is one argument of its own, so nothing in it
	is interpreted by a shell.
	'''
	return http_recon_command(target)


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
    #print(o)

    try:
        for host in o['nmaprun']['host']['ports']['port']:
                out_json ={}
                out_json['type'] ="nmap"
                out_json['scanner'] ="nmap_httpd"
                out_json['target']="{0}".format(os.environ['TARGET'])
                out_json['result'] = host
                out_json['runstats']= o['nmaprun']['runstats']
                #print(port)
                logger(out_json)
                #o['nmaprun']['host']['ports']['port']=port
                #json_out = json.dumps(o)
                #print json_out
                #add_to_que(str(json_out))



    except KeyError:
        json_out = json.dumps(o)
        #print(json_out)


if __name__ == '__main__':
    #Refuse a bad target before anything runs, then scan and get the output
    target = require_valid_target()
    start_scan(target)
    convert_output()
    endThis()
