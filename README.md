#### Nmap scanner for samma.
Scans the target ip and send result back to samma.io ore Elasticsearch server.




## use with docker compose ore docker run command


#For output to Elastic
docker run -it -e target=IP -e out=Elasticsearch -e es_host=http://elasticsearch -e es_user=elastic -e es_pass=changeme samma_scanner/nmap
#
for output to samma.io
docker run -it -e target=IP -e out=Elasticsearch -e es_host=http://elasticsearch -e es_user=elastic -e es_pass=changeme samma_scanner/nmap

