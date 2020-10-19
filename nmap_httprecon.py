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
	process = subprocess.Popen('nmap -sV --script http-enum  {0} -oX result_h.xml '.format(os.environ['TARGET']) , shell=True, stdout=subprocess.PIPE)
	process.wait()



def convert_output():
    '''
    Converts the output to json
    '''
    f = open("result_h.xml","r") 
    text = f.read()
    o = xmltodict.parse(text)


    try:
        for host in o['nmaprun']['host']:
            for port in host['ports']['port']:
                out_json ={}
                out_json['type'] ="Nmap Scan httpd" 
                out_json['target']="{0}".format(os.environ['TARGET'])
                out_json['result'] = port
                out_json['runstats']= o['nmaprun']['runstats']
                #print(port)
                print(json.dumps(out_json))
                #o['nmaprun']['host']['ports']['port']=port
                #json_out = json.dumps(o)
                #print json_out
                #add_to_que(str(json_out))



    except KeyError:
        json_out = json.dumps(o)
        print(json_out)
start_scan()
convert_output()