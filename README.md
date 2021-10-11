# Samma Security Scanner Nmap

![Samma-io!](/assets/samma_logo.png)




## Samma Security Scanners
This scanner is part of the Samma Security Scanners

The Samma Security Scanners are all small openspurce scanners. That have ben docerixed and print there result in JSON format.
The result is then sent to ElasticSerarch for storage and displayed using Kibana ore Grafana.

To see all the scanners please go to [Samma.io](https://samma.io)


## Start with Highground 
Highground is a colelctions of Elasticsearch ,Kibana and Grafana that is put toghter. 
Its ready so that the different scanners can send there result into Elasticsearch and then use the pre ready dashbourds to show the result.


You can send result with the attaced filebeat that send logs directly ore use your normal stput log flow.
Then save the logs in the samma-io index to use our pre dashbourds.


## Start with console
All Samma Security scanners can be run from the command line to scan then output the result in JSON. This make its easy to integrate the scanner into diffrent piplines but also test the scanners localy


```
docker run sammascanner/nmap -e TARGET=samma-io 
```

## Docker-compose
All repos has a responding docker compose to setup and test localy on a developer machine. Start by sarting up highground to get the dashbourds ready.
Then start the scanner you want to run against your targets.


## Kubernetes 
All repos has manifest so that you can deploy your scanners into your own kubernetes cluster. The manifest are mostly testet aginst minkube but will work against any kubernetes cluster.

## Helm
I helm repo is avalibel to deploy scanners with helm. This can be used to example deploy scanner into the cluster in the pipeline ore into a productions scanner cluster.

[Samma Helm Charts](https://github.com/samma-io/helm)

## Help
Help is provided by the bravops team at [Braveops](https://braveops.io) 



