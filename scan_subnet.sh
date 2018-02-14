#!/bin/bash
echo "Scanning subnet 10.100.0.1-10.100.0.255"

COUNTER=1
while [ $COUNTER -lt 256 ]
do
	echo "print $COUNTER"
	docker run -it -e TARGET=10.0.0.$COUNTER -e RABBIT=10.100.0.37 sammascanner/nmap 

	let COUNTER=COUNTER+1
done



