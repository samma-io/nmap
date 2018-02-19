# Nmap scanner for samma.io


Scans the target ip and send result and rabbitmq server 

Ue the samma.io stack to get the ful stack to use to get data.
###scanner -> rabbitmq -> logstash -> Elasticsearch <- Kibana


All scans are done and if found open port a json is sent to ELK with host data. The scanner logs every openport into elastic.
It host is down ore no ports is open a log is sent saying host down ore no ports open.


Use Kibana tp graf and search into findings


## Bring up stack 
First bring up the samma.io stack found here


## Start a scan 


```
docker run -it -e TARGET=10.0.0.1 -e RABBIT=10.100.0.37 sammascanner/nmap 

```
Replace the ip to the one for you traget and rabbitmq



To use TLS rabbit not in the samma.io stack today

```
docker run -it -e TARGET=10.0.0.$COUNTER -e RABBIT=10.100.0.37 -e TLS=yes sammascanner/nmap 

```


## Scripted to scan subnet
```
#!/bin/bash
echo "Scanning subnet 10.100.0.1-10.100.0.255"

COUNTER=1
while [ $COUNTER -lt 256 ]
do
	echo "print $COUNTER"
	docker run -it -e TARGET=10.0.0.$COUNTER -e RABBIT=10.100.0.37 sammascanner/nmap 

	let COUNTER=COUNTER+1
done
```


Replace the values with your values

## Enviroment setting


###TARGET = the host you want to scan a IP example 10.0.0.1 (No SUBNET support yeat)

###RABBIT  = IP to rabbit server

###TLS = If set connect to rabbot over port 5671 and use TLS (ssl support)  



#### Happy scanning 