#!/usr/bin/env python

import sys
import signal
import os
from os.path import exists
from scapy.all import *

def close_handler(signal, frame):
    sys.exit(0)
signal.signal(signal.SIGINT, close_handler)

packet=sniff(filter="dst port 22 && src port 20",count=1)
number=(packet[0][TCP].chksum) 

#print(number)  #prints decimal

if number < 0x1:
   number=str(hex(number))
   number='0000'                #no swap bytes needed
elif number < 0x10:
   number=str(hex(number))
#   number='0'+number[2]+ '00'   #swap bytes 
   number='000'+number[2]        #don't swap bytes 
elif number < 0x100:
   number=str(hex(number))
#   number=number[2]+number[3]+'00' #swap bytes 
   number='00' +number[2]+number[3] #don't swap bytes
elif number < 0x1000:
   number=str(hex(number))
#   number=number[3]+number[4]+'0'+number[2] #swap bytes
   number='0'+number[2]+number[3]+number[4] #don't swap bytes
else:
   number=str(hex(number))
#   number=number[4]+number[5]+number[2]+number[3] #swap bytes
   number=number[2]+number[3]+number[4]+number[5] #don't swap bytes

print(number) #prints hex chars

File_object = open(r"tempfile4nreceive1","a")
File_object.write(number) #scapy sends TCPcksum in network order
File_object.close()

exit()
