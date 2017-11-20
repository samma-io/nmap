from ubuntu


#Install nmap
RUN apt-get update && apt-get install nmap python-pip -y
RUN pip install --upgrade pip
RUN pip install xmltodict


COPY run.py /run.py
RUN chmod 700 /run.py


CMD /run.py
