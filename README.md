# endpoint--firewall
## Description
This is a simple endpoint firewall protect device form DDOS attacks and DNS spoofing and ARP spoofing and have a number of options will be discused below.<be>

## How to download
``` git clone  https://github.com/Hackmain/endpoint--firewall.git```<br>
after that make sure run this command:<br>
```pip install -r requirements.txt``` use sudo before it got issues


## Usage
if you write the command with the option -sniff it not work make sure add interface option 
after bring it from the commands : <br>
``` ip a``` or ```ifconfig ``` in my case i using "eth0"
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
  
## The attacks that been blocked or stoped are:
* Dns Spoofing
* Arp Spoooing
* DDOS Attak And the ip will blocked automaticaly when it is reached the limit number of requests.

@ALL ATTACKS WILL BLOCKED@
!tcpfirewall.png

## Contect
* 1- instagram : @esefkh740_
* 2- telegram : @jkak4
* 3- github : https://github.com/Hackmain
