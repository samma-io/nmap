# -*- coding: utf-8 -*-
##
##
#
# Start the nmap scan and wait for it to complete.
# Then format the resonse and send the data back to the server
#
import os
import sys
import xmltodict, json
from sammaParser import logger, endThis
from target_check import require_valid_target, _write_die
import nmap_args
import nmap_xml
from nmap_args import http_recon_command


def nmap_command(target):
	'''
	The nmap argv list, built by nmap_args. By default nmap runs through
	sudo; with NMAP_UNPRIVILEGED=1 it runs without sudo (and
	with NMAP_PRIVILEGED=1 from the nmap-raw copy, also without sudo). Version detection
	and the http-enum script need no raw sockets, so the flags are the same
	in both modes. The target is one argument of its own, so nothing in it
	is interpreted by a shell.
	'''
	return http_recon_command(target)


def start_scan(target):
	'''
	Start the nmap scan of the target. False when nmap could not start.
	'''
	return nmap_args.run(nmap_command(target))



def convert_output(doc):
    '''
    One record per port in the report, carrying the port element as nmap
    wrote it. A down host gives no records.
    '''
    for port in nmap_xml.ports(doc):
        out_json ={}
        out_json['type'] ="nmap"
        out_json['scanner'] ="nmap_httpd"
        out_json['target']="{0}".format(os.environ['TARGET'])
        out_json['result'] = port
        out_json['runstats']= nmap_xml.runstats(doc)
        logger(out_json)


if __name__ == '__main__':
    #Refuse a bad target before anything runs, then scan and get the output
    target = require_valid_target()
    start_scan(target)
    doc = nmap_xml.read_report(xmltodict.parse)
    if doc is None:
        # nmap failed: no "scan done" record, exit non-zero like a bad target
        _write_die("/out/die")
        sys.exit(1)
    convert_output(doc)
    endThis()
