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
	process = subprocess.Popen('nmap -sV --script ssl-enum-ciphers  {0} -oX result.xml '.format(os.environ['TARGET']) , shell=True, stdout=subprocess.PIPE)
	process.wait()



def convert_output():
    '''
    Converts the output to json
    '''
    f = open("result.xml","r") 
    text = f.read()
    o = xmltodict.parse(text)


    
    for host in o['nmaprun']['host']:
        try:
            for port in host['ports']['port']:
                out_json ={}
                out_json["type"] ="NmapScanTLS" 
                out_json['target']="{0}".format(os.environ['TARGET'])
                out_json['service'] = port['service']
                #out_json['version'] = port['service']['@version']
                out_json['tls']= port['script']['table']
                #out_json['runstats']= o['nmaprun']['runstats']
                print(json.dumps(out_json))
        except KeyError:
                out_json ={}
                out_json["type"] ="NmapScanTLS" 
                out_json['target']="{0}".format(os.environ['TARGET'])
                print(out_json)
start_scan()
convert_output()