from ubuntu


#Install nmap
RUN apt-get update && apt-get install nmap python3-pip -y
RUN pip3 install --upgrade pip
RUN pip3 install xmltodict amqplib


COPY  . /code
RUN chmod 700 /code/nmap_*


CMD python3 /code/nmap_portscanner.py
