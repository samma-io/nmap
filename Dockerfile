# Ubuntu 24.04 LTS, pinned by digest so a rebuild gets the same base.
# Bump the tag and digest together: docker buildx imagetools inspect ubuntu:24.04
FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac


#Install nmap
RUN apt-get update && apt-get install sudo nmap libcap2-bin python3-pip -y
RUN pip3 install xmltodict nats-py --break-system-packages

# Raw-sockets mode (NMAP_PRIVILEGED=1, a pod with every capability dropped but
# NET_RAW added): a copy of nmap that gets CAP_NET_RAW from a file capability,
# so it runs as samma without sudo. Only nmap_args.py calls it, and only in
# that mode. /bin/nmap stays without a capability: the kernel refuses to exec
# a binary whose effective file capabilities it cannot grant, which would
# break the default and unprivileged modes in a pod without NET_RAW.
RUN install -D -o root -g root -m 0755 /usr/bin/nmap /usr/local/lib/samma/nmap-raw \
 && setcap cap_net_raw+eip /usr/local/lib/samma/nmap-raw \
 && getcap /usr/local/lib/samma/nmap-raw | grep -q cap_net_raw \
 && test -z "$(getcap /usr/bin/nmap)"


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
