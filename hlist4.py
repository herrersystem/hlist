#!/usr/bin/env python
# -*- coding:utf-8 -*-

'''
Inspiré d'un script de Krig (lien ci-dessous).
https://github.com/krig/send_arp.py
'''

import socket, codecs, os
import argparse


def conversionHexIP(adresse):
	adresseHex=str()
	
	for element in adresse.split('.'): 
		tmp=str(hex(int(element)))[2:]
		
		if len(tmp) < 2: 
			tmp='0'+tmp
		
		adresseHex+=tmp
	
	return adresseHex
	
	
def conversionGraphMac(adresse):
	return adresse[:2]+':'+adresse[2:4]+':'+adresse[4:6]+':'+adresse[6:8]+':'+adresse[8:10]+':'+adresse[10:12]


def conversionHexMac(adresse):
	adresseHex=str()
	
	for element in adresse.split(':'): 
		adresseHex+=element
	
	return adresseHex


def ethernet(src, dst):
	dst=conversionHexMac(dst)
	src=conversionHexMac(src)
	protocole='0806' #Protocole ARP.
	
	return dst+src+protocole


def arp(hsrc, src, dst):
	htype='0001'
	ptype='0800'
	hlenght='06'
	plenght='04'
	operation='0001' #Arp request.
	hsrc=conversionHexMac(hsrc)
	psrc=conversionHexIP(src)
	hdst='000000000000'
	pdst=conversionHexIP(dst)
	
	return htype+ptype+hlenght+plenght+operation+hsrc+psrc+hdst+pdst


def monAdresseIP(interface):
	ipconfig=os.popen('ifconfig %s'%interface).readlines()
	motcle='inet adr:'
	motcle2='Bcast:'
	indice=ipconfig[1].find(motcle)
	indice2=ipconfig[1].find(motcle2)
	
	if indice != -1 and indice2 != -1: 
		indice+=len(motcle)
		padresse=ipconfig[1][indice:indice2-1]
		
	else: 
		padresse=False
	
	return padresse
	
	
def monAdresseMac(interface):
	ipconfig=os.popen('ifconfig %s'%interface).readlines()
	motcle='HWaddr '
	indice=ipconfig[0].find(motcle)
		
	if indice != -1: 
		indice+=len(motcle)
		hadresse=ipconfig[0][indice:indice+17]
		
	else: 
		hadresse=False
	
	return hadresse


def listeAdresse(fourchette):
	liste=list()
	
	if len(fourchette.split('-')) == 2:
		tmp, borneMax=arg.f.split('-')
		tmp=tmp.split('.')
		statique="{}.{}.{}.".format(tmp[0], tmp[1], tmp[2])
		borneMin=tmp[3]
		
		if int(borneMin) > int(borneMax): 
			liste.append(False)
			
		else:
			for i in range(int(borneMin), int(borneMax)+1): 
				liste.append(statique+str(i))
		
	elif len(fourchette.split('-')) == 1: 
		liste.append(fourchette)
		
	else: 
		liste.append(False)
	
	return liste


def envoiRequete(interface, liste, maMac, monIp):
	global parser
	
	if liste[0] != False:
		s=socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
		s.settimeout(2)
		s.bind((interface, socket.SOCK_RAW))
	
		headerEther=ethernet(maMac, 'ff:ff:ff:ff:ff:ff')
		for cible in liste:
			try:
				headerArp=arp(maMac, monIp, cible)
				s.send(codecs.decode(headerEther+headerArp, 'hex_codec'))
				rep=s.recv(32)
				rep=codecs.encode(rep, 'hex_codec')
				
				if len(rep) == 64:
					mac=rep.decode()[12:24]
					proto=rep.decode()[24:28]
					op=rep.decode()[43]
					ip=rep.decode()[56:64]
					
					if proto == "0806" and op == '2' and ip == conversionHexIP(cible): 
						print("> [{}] {} ({})".format(
							socket.gethostbyaddr(cible)[0], cible, conversionGraphMac(mac))
						)
						
			except socket.timeout: 
				pass
				
			except socket.gaierror: 
				parser.print_help()
		
		s.close()
		
	else: 
		parser.print_help()


if __name__ == '__main__':
	parser=argparse.ArgumentParser(prog='hlist4', 
		description='Découverte d\'hôte via ARP')
	parser.add_argument('-i', action='store', metavar='interface', required=True, 
		help='Interface à utiliser')
	parser.add_argument('-f', action='store', metavar='fourchette', required=True, 
		help='Adresse(s) à scanner (ex: 192.168.1.21-52 ou 192.168.1.21)')
	arg=parser.parse_args()
	
	interface=arg.i
	liste=listeAdresse(arg.f)
	maMac=monAdresseMac(interface)
	monIp=monAdresseIP(interface)
	
	if not maMac or not monIp: 
		print("> [ERR] interface %s non trouvée"%interface) 
		
	else: 
		envoiRequete(interface, liste, maMac, monIp)
	
