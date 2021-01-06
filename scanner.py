#!/usr/bin/env python3
import nmap
import socket

scanner=nmap.PortScanner()


print("WELCOME TO MY DUNGEON :-)")

print("-----------------")

print("NMAP VERSION YOU ARE USING:",scanner.nmap_version())

print('*'*60)

ip_addr=input("[*] ENTER THE HOST NAME OR IP ADDRESS TO SCAN :")

print("YOU WANNA DOOM THIS IP ::",ip_addr)

type(ip_addr)

resp= input("""\nYOUR CHOICE OF SCAN 
			1)SYN-ACK SCAN	
			2)UDP SCAN
			3)COMPREHENSIVE SCAN
			\n""")

print("NICE CHOICE :D",resp)

if resp=='1':
	
	scanner.scan(ip_addr,'1-1024','-v  -sS')
	print(scanner.scaninfo())
	print("[*]THE IP STATUS IS :",scanner[ip_addr].state())
	print("[*] THE PROTOCOL IS:",scanner[ip_addr].all_protocols())
	print("[*] OPEN PORTS:",scanner[ip_addr]['tcp'].keys())
elif resp=='2':
	try:
		scanner.scan(ip_addr,'1-1024','-v -sU')
		print(scanner.scaninfo())
		print("[*] THE IP STATUS IS :",scanner[ip_addr].state())
		print("[*] THE PROTOCOL IS:",scanner[ip_addr].all_protocols())
		print("[*] OPEN PORTS :",scanner[ip_addr]['udp'].keys())
	except Exception:
		print("[*] PLEASE USE SUDO FOR THIS SCAN :(((")

elif resp=='3':

	try:
		scanner.scan(ip_addr,'1-1024','-v -sS -sV -A -O')
		print(scanner.scaninfo())
		print("[*] THE IP STATUS IS :",scanner[ip_addr].state())
		print("[*] THE PROTOCOL IS:",scanner[ip_addr].all_protocols())
		print("[*] OPEN PORTS :",scanner[ip_addr]['tcp'].keys())
	except Exception:
		print("[*] NOT AGAIN PLEASE USE SUDO FOR THIS SCAN :(((")
else:
	print("HANGOVER HUH??")
	print("?"*40)













