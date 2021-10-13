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




def start_scan():
	'''
	Start the nmap scan of the target
	'''
	process = subprocess.Popen('sudo /bin/nmap -sV --script ssl-enum-ciphers  {0} -oX /out/result.xml '.format(os.environ['TARGET']) , shell=True, stdout=subprocess.PIPE)
	process.wait()



def convert_output():
    '''
    Converts the output to json
    '''
    f = open("/out/result.xml","r") 
    text = f.read()
    o = xmltodict.parse(text)
    json_data = json.dumps(o)
    #print(o)

    
    for host in o['nmaprun']['host']['ports']['port']:
        try:
                out_json ={}
                out_json['type'] ="nmap"
                out_json['scanner'] ="nmap_tls" 
                out_json['target']="{0}".format(os.environ['TARGET'])
                out_json['service'] = host['service']
                #out_json['version'] = port['service']['@version']
                #out_json['tls']= host['script']['table']
                #out_json['runstats']= o['nmaprun']['runstats']
                logger(out_json)

        except KeyError:
                out_json ={}
                out_json["type"] ="NmapScanTLS" 
                out_json['target']="{0}".format(os.environ['TARGET'])
                logger(out_json)

start_scan()
convert_output()
endThis()