# endpoint--firewall
## Description
This is a simple endpoint firewall protect device form DDOS attacks and DNS spoofing and ARP spoofing and have a number of options will be discused below.<be>

## How to download
``` git clone  https://github.com/Hackmain/endpoint--firewall.git```

## Usage
* 1-Sniff Packets:
  ```sudo python3 fire.py -sniff -interface eth0```
* 2-Add IP to Allowed List:
  ```sudo python3 fire.py -add_ip 192.168.1.20```
* 3-Block IP:
  ```sudo python3 fire.py -block_ip 203.0.113.5```
* 4-Add Port to Allowed List:
  ```sudo python3 fire.py -add_port 8080```
* 5-Block Port:
  ```sudo python3 fire.py -block_port 25```


