from ubuntu


#Install nmap
RUN apt-get update && apt-get install sudo nmap python3-pip -y
RUN pip3 install --upgrade pip
RUN pip3 install xmltodict amqplib


COPY  . /code
RUN chmod 700 /code/nmap_*

RUN mkdir /output
RUN mkdir /out

RUN useradd -ms /bin/bash samma
RUN chown samma:samma /out
RUN chown samma:samma /output
RUN chown samma:samma /code/*.py
RUN chmod 664 /code/*.py

RUN echo "samma ALL=NOPASSWD: /bin/nmap" >> /etc/sudoers
USER samma
WORKDIR /output 




CMD python3 /code/nmap_portscanner.py
