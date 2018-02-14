from ubuntu


#Install nmap
RUN apt-get update && apt-get install nmap python-pip -y
RUN pip install --upgrade pip
RUN pip install xmltodict amqplib


COPY  . /code
RUN chmod 700 /code/run.py


CMD python /code/run.py
