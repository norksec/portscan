#!/bin/usr/python

#norksec portscan - no rights reserved

import optparse
import atexit
import os
from pyfiglet import Figlet
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def cls():	
	os.system('cls' if os.name=='nt' else 'clear')

def intro():
	fa = Figlet(font='graffiti')
	print fa.renderText('NoRKSEC')
	print '\nPortScan v1.0 - (c) 2016 NoRKSEC - no rights reserved\n\n'

def connScan(tgtHost, tgtPort):
	try:
		connSkt = socket(AF_INET, SOCK_STREAM)
		connSkt.connect((tgtHost, tgtPort))
		connSkt.send('BestKoreaForever\r\n')
		results = connSkt.recv(100)
		screenLock.acquire()
		print '[+] %d/tcp open' % tgtPort
		print '[+] ' + str(results)
	except:
		screenLock.acquire()
		print '[-] %d/tcp closed' % tgtPort
	finally:
		screenLock.release()
		connSkt.close()

def portScan(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print "[-] Cannot resolve '%s': Unknown host." % tgtHost
		return
	try:
		tgtName = gethostbyaddr(tgtIP)
		print '\n[+] Scan Results for: ' + tgtName[0]
	except:
		print '\n[+] Scan Results for: ' + tgtIP
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
		t.start()
	
def exit_handler():
	print '\n[+] Exiting...\n'

def main():
	atexit.register(exit_handler)
	parser = optparse.OptionParser('%prog -H <target host> -p <target port>')
	parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
	parser.add_option('-p', dest='tgtPort', type='string', help='specify target ports seperated by commas <eg: 21,25,80>')
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	tgtPorts = str(options.tgtPort).split(',')

	if (tgtHost == None) | (tgtPorts[0] == None):
		print parser.error('Invalid arguments.')
		exit(0)
	portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
	cls()
	intro()
	main()
