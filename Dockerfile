from ubuntu


#Install nmap
RUN apt-get update && apt-get install sudo nmap python3-pip -y
RUN pip3 install xmltodict nats-py --break-system-packages


COPY  . /code
RUN chmod 700 /code/nmap_*

RUN mkdir /out

# ubuntu:latest ships an "ubuntu" user at uid/gid 1000 (and in the sudo group),
# so a plain useradd would give samma uid 1001. The samma operator runs scanner
# containers with runAsUser 1000 and the sudoers rule below names samma, so
# samma has to be uid/gid 1000: drop the stock user and pin the ids.
RUN if id ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi \
 && if getent group ubuntu >/dev/null; then groupdel ubuntu; fi \
 && groupadd --gid 1000 samma \
 && useradd --uid 1000 --gid 1000 -ms /bin/bash samma
RUN chown samma:samma /out
RUN chown samma:samma /code/*.py
RUN chmod 664 /code/*.py

RUN echo "samma ALL=NOPASSWD: /bin/nmap" >> /etc/sudoers
USER samma



CMD python3 /code/nmap_portscanner.py
