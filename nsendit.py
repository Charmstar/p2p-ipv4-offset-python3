#!/usr/bin/env python
#This is nsendit.py to be used with nreceive1.py on one end and with nreceive.py on the other end. 
#nsendit.py begins by sending two normal outgoing SYNs.
#If nreceive1.py does not capture the first normal outgoing descernible SYN then it will be certain to capture the second one. 
#In any case, nreceive1.py is able to pass a normal SYN's TCPcksum to nsendit.py in the tempfile4nreceive1 file.

#IMPORTANT: REMEMBER TO EXIT NRECEIVE.PY ON THIS END BEFORE STARTING 
#python3 nsendit.py ON THIS END. 

from scapy.all import *
import sys
import codecs
import os
from contextlib import suppress
from os.path import exists
import time
w=0 
N=1
x=0
cnt=0
cnt2=0

if(exists("tempfile4nreceive1")):
    os.remove("tempfile4nreceive1")

FILE=sys.argv[2]    # USAGE: python3 nsendit.py IP4DEST FILE
IP4DEST=sys.argv[1] # USAGE: python3 nsendit.py IP4DEST FILE

os.system('python3 nreceive1.py &')
time.sleep(2) #2 secs may be enough time for nreceive1.py to get started? 

p=IP(dst=IP4DEST)/TCP(dport=22, sport=20) #1st out is normal SYN packet
send(p) #nreceive1.py may not get started in time for this SYN?

time.sleep(2) #add some more time for nreceive1.py to get started
p=IP(dst=IP4DEST)/TCP(dport=22, sport=20) #2nd out is normal SYN packet
send(p)

while not os.path.exists('tempfile4nreceive1'):
    continue

file_object = open("tempfile4nreceive1", "r")
if file_object.mode == 'r':
    contents=file_object.read()
ESCAPE=contents
print(ESCAPE)

FH=open(FILE, 'rb') #'rb' avoids UTF-8 read error
while 1:
       Y=codecs.encode(FH.read(1), 'hex')
       Z=codecs.encode(FH.read(1), 'hex')
       X=Z+Y #byte swap needed 
       if X==b"":
          FH.close()
          break
       if X == b'ffff':
          cnt += 1
       if int(X,16) ==int(ESCAPE,16):
          cnt2 += 1
       continue
print("Number of FFFFs is ", cnt)
print("      Number of ESCAPEs is ", cnt2)

p=IP(dst=IP4DEST)/TCP(dport=22,sport=20,chksum=65535) #1st of two OFFSET packets
send(p)
print("There goes ffff")
p=IP(dst=IP4DEST)/TCP(dport=22,sport=20,chksum=0) #2nd of two OFFSET packets
send(p)
print("There goes 0000") 
SIZE=os.path.getsize(FILE)
if SIZE+1>>1 != SIZE>>1:
   SIZE=SIZE+1>>1
else:
   SIZE=SIZE>>1
SIZE=SIZE+cnt+cnt2

p=IP(dst=IP4DEST)/TCP(dport=22,sport=20,chksum=SIZE) 
send(p) #five packet preamble is complete
print("There goes transmission SIZE ", SIZE)

packet=sniff(filter="tcp[tcpflags] & tcp-syn !=0 && tcp[tcpflags] & tcp-ack ==0 && dst port 22 && src port 20",count=1) 
#sniff for RECEIVER's ack, then begin while loop:

FH=open(FILE, 'rb') 
while 1:
   print("Packet No. ", N)
   N+=1  
#   X=codecs.encode(FH.read(2), 'hex') #python2 prints 5468 ASCII hex for Th
#   X=codecs.encode(FH.read(2), 'utf_8') #arg 1 must be string, not bytes
   Y=codecs.encode(FH.read(1), 'hex')
   Z=codecs.encode(FH.read(1), 'hex')
   X=Z+Y #byte swap needed for little-endian CPU to send in network order
   time.sleep(0.1) #slow down fast sender for slow receiver
#   time.sleep(0.25) #may prevent dropped packets due to buffer overrun  
    print(X)
   if X==b'':
      FH.close()
      exit()
   elif X==b'ffff':
      p=IP(dst=IP4DEST)/TCP(dport=22, sport=20) #send an ESCAPE packet
      print("Sending ESCAPE SYN for ffff")
      send(p)
      print("Sending ffff")   
      p=IP(dst=IP4DEST)/TCP(dport=22, sport=20, chksum=65535) #sending 0xffff
      send(p)
   elif int(X,16) ==int(ESCAPE,16):
      p=IP(dst=IP4DEST)/TCP(dport=22, sport=20) #send an ESCAPE packet
      print("Sending double ESCAPE packets")
      send(p)
      p=IP(dst=IP4DEST)/TCP(dport=22, sport=20) #send another ESCAPE packet
      send(p)
   else:
      p=IP(dst=IP4DEST)/TCP(dport=22, sport=20, chksum=int(X,16))
      send(p)
   continue
