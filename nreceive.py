#!/usr/lib/env python
import time
import signal
import codecs
import os
from os.path import exists
from scapy.all import *
from contextlib import suppress

count=0
N=0
i=0
n=4
charnum='0000'
global PASSTHRU
PASSTHRU=0
OFFSETB=0x0

def olookup(W):
   FH=open("bintranslatedbinaryout", "ab") #ab works, not a alone
   FH.write(dct0[W])
   FH.close

dct0={"00":b'\x00',"01":b'\x01',"02":b'\x02',"03":b'\x03',"04":b'\x04',"05":b'\x05',"06":b'\x06',"07":b'\x07',"08":b'\x08',"09":b'\x09',"0a":b'\x0a',"0b":b'\x0b',"0c":b'\x0c',"0d":b'\x0d',"0e":b'\x0e',"0f":b'\x0f'}
dct1={"10":b'\x10',"11":b'\x11',"12":b'\x12',"13":b'\x13',"14":b'\x14',"15":b'\x15',"16":b'\x16',"17":b'\x17',"18":b'\x18',"19":b'\x19',"1a":b'\x1a',"1b":b'\x1b',"1c":b'\x1c',"1d":b'\x1d',"1e":b'\x1e',"1f":b'\x1f'}
dct2={"20":b'\x20',"21":b'\x21',"22":b'\x22',"23":b'\x23',"24":b'\x24',"25":b'\x25',"26":b'\x26',"27":b'\x27',"28":b'\x28',"29":b'\x29',"2a":b'\x2a',"2b":b'\x2b',"2c":b'\x2c',"2d":b'\x2d',"2e":b'\x2e',"2f":b'\x2f'}
dct3={"30":b'\x30',"31":b'\x31',"32":b'\x32',"33":b'\x33',"34":b'\x34',"35":b'\x35',"36":b'\x36',"37":b'\x37',"38":b'\x38',"39":b'\x39',"3a":b'\x3a',"3b":b'\x3b',"3c":b'\x3c',"3d":b'\x3d',"3e":b'\x3e',"3f":b'\x3f'}
dct4={"40":b'\x40',"41":b'\x41',"42":b'\x42',"43":b'\x43',"44":b'\x44',"45":b'\x45',"46":b'\x46',"47":b'\x47',"48":b'\x48',"49":b'\x49',"4a":b'\x4a',"4b":b'\x4b',"4c":b'\x4c',"4d":b'\x4d',"4e":b'\x4e',"4f":b'\x4f'}
dct5={"50":b'\x50',"51":b'\x51',"52":b'\x52',"53":b'\x53',"54":b'\x54',"55":b'\x55',"56":b'\x56',"57":b'\x57',"58":b'\x58',"59":b'\x59',"5a":b'\x5a',"5b":b'\x5b',"5c":b'\x5c',"5d":b'\x5d',"5e":b'\x5e',"5f":b'\x5f'}
dct6={"60":b'\x60',"61":b'\x61',"62":b'\x62',"63":b'\x63',"64":b'\x64',"65":b'\x65',"66":b'\x66',"67":b'\x67',"68":b'\x68',"69":b'\x69',"6a":b'\x6a',"6b":b'\x6b',"6c":b'\x6c',"6d":b'\x6d',"6e":b'\x6e',"6f":b'\x6f'}
dct7={"70":b'\x70',"71":b'\x71',"72":b'\x72',"73":b'\x73',"74":b'\x74',"75":b'\x75',"76":b'\x76',"77":b'\x77',"78":b'\x78',"79":b'\x79',"7a":b'\x7a',"7b":b'\x7b',"7c":b'\x7c',"7d":b'\x7d',"7e":b'\x7e',"7f":b'\x7f'}
dct8={"80":b'\x80',"81":b'\x81',"82":b'\x82',"83":b'\x83',"84":b'\x84',"85":b'\x85',"86":b'\x86',"87":b'\x87',"88":b'\x88',"89":b'\x89',"8a":b'\x8a',"8b":b'\x8b',"8c":b'\x8c',"8d":b'\x8d',"8e":b'\x8e',"8f":b'\x8f'}
dct9={"90":b'\x90',"91":b'\x91',"92":b'\x92',"93":b'\x93',"94":b'\x94',"95":b'\x95',"96":b'\x96',"97":b'\x97',"98":b'\x98',"99":b'\x99',"9a":b'\x9a',"9b":b'\x9b',"9c":b'\x9c',"9d":b'\x9d',"9e":b'\x9e',"9f":b'\x9f'}
#dct9={"90":b'\x90',"91":b'\x91',"92":b'\x92',"93":b'\x93',"94":b'\x94',"95":b'\x95',"96":b'\x96',"97":b'\x97',"98":b'\x98',"99":b'\x99',"9a":b'\x9a',"9b":b'\x9b',"9c":b'\x9c',"9d":b'\x9d',"9e":b'\x9e',"9f":b'\x9f'}
dcta={"a0":b'\xa0',"a1":b'\xa1',"a2":b'\xa2',"a3":b'\xa3',"a4":b'\xa4',"a5":b'\xa5',"a6":b'\xa6',"a7":b'\xa7',"a8":b'\xa8',"a9":b'\xa9',"aa":b'\xaa',"ab":b'\xab',"ac":b'\xac',"ad":b'\xad',"ae":b'\xae',"af":b'\xaf'}
dctb={"b0":b'\xb0',"b1":b'\xb1',"b2":b'\xb2',"b3":b'\xb3',"b4":b'\xb4',"b5":b'\xb5',"b6":b'\xb6',"b7":b'\xb7',"b8":b'\xb8',"b9":b'\xb9',"ba":b'\xba',"bb":b'\xbb',"bc":b'\xbc',"bd":b'\xbd',"be":b'\xbe',"bf":b'\xbf'}
dctc={"c0":b'\xc0',"c1":b'\xc1',"c2":b'\xc2',"c3":b'\xc3',"c4":b'\xc4',"c5":b'\xc5',"c6":b'\xc6',"c7":b'\xc7',"c8":b'\xc8',"c9":b'\xc9',"ca":b'\xca',"cb":b'\xcb',"cc":b'\xcc',"cd":b'\xcd',"ce":b'\xce',"cf":b'\xcf'}
dctd={"d0":b'\xd0',"d1":b'\xd1',"d2":b'\xd2',"d3":b'\xd3',"d4":b'\xd4',"d5":b'\xd5',"d6":b'\xd6',"d7":b'\xd7',"d8":b'\xd8',"d9":b'\xd9',"da":b'\xda',"db":b'\xdb',"dc":b'\xdc',"dd":b'\xdd',"de":b'\xde',"df":b'\xdf'}
dcte={"e0":b'\xe0',"e1":b'\xe1',"e2":b'\xe2',"e3":b'\xe3',"e4":b'\xe4',"e5":b'\xe5',"e6":b'\xe6',"e7":b'\xe7',"e8":b'\xe8',"e9":b'\xe9',"ea":b'\xea',"eb":b'\xeb',"ec":b'\xec',"ed":b'\xed',"ee":b'\xee',"ef":b'\xef'}
dctf={"f0":b'\xf0',"f1":b'\xf1',"f2":b'\xf2',"f3":b'\xf3',"f4":b'\xf4',"f5":b'\xf5',"f6":b'\xf6',"f7":b'\xf7',"f8":b'\xf8',"f9":b'\xf9',"fa":b'\xfa',"fb":b'\xfb',"fc":b'\xfc',"fd":b'\xfd',"fe":b'\xfe',"ff":b'\xff'}
dct0=dctf|dct0      
dct0=dcte|dct0      
dct0=dctd|dct0      
dct0=dctc|dct0      
dct0=dctb|dct0      
dct0=dcta|dct0      
dct0=dct9|dct0      
dct0=dct8|dct0      
dct0=dct7|dct0      
dct0=dct6|dct0      
dct0=dct5|dct0      
dct0=dct4|dct0      
dct0=dct3|dct0      
dct0=dct2|dct0      
dct0=dct1|dct0      


if(exists("translatedbinaryout")):
    os.remove("translatedbinaryout")
if(exists("bintranslatedbinaryout")):
    os.remove("bintranslatedbinaryout")

with suppress(Exception):
    packet=sniff(filter="tcp[tcpflags] & tcp-syn!=0 && tcp[tcpflags] & tcp-ack==0 && dst port 22 && src port 20", count=5)
packet[0].show()
if packet[2][TCP].chksum == packet[3][TCP].chksum:
   OFFSETB= packet[3][TCP].chksum 
else:
    OFFSETB=0x0
ESCAPE=packet[0][TCP].chksum-OFFSETB
if(ESCAPE<0x0):
    ESCAPE=ESCAPE+0xFFFF
print(hex(ESCAPE))
Z=packet[4][TCP].chksum-OFFSETB
if(Z<0x0):
   Z=Z+0xFFFF

LENGTH=Z
print("LENGTH IS ", Z)
print("This is OFFSETB", hex(OFFSETB))
tempo= datetime.now()
print("Time is now ") 
print(tempo)

p=Ether(dst=packet[2][Ether].src)/IP(dst=packet[0][IP].src)/TCP(dport=22, sport=20) #ACK rec'd opening five SYN preamble - use received SYN's source MAC Ether
    #address to respond to avoid scapy's default to use MAC broadcast #address.
time.sleep(2) #add some time for SENDER to start sniff after sending preamble
sendp(p)

with suppress(Exception): #A single dropped packet will cause sniff to stall.
    #Ctl-C breaks the stall and gives SENDER the option to fallback to
    #plaintext. Suppressing the exception allows sniff to finish capturing 
    #when network conditions persistently prevent decrypting encrypted files.
     packet=sniff(filter="tcp[tcpflags] & tcp-syn!=0 && tcp[tcpflags] & tcp-ack==0 && dst port 22 && src port 20", count=LENGTH) 

def packed(LENGTH, PASSTHRU):
 with suppress(Exception):
  for i in range(LENGTH): 
      print("Received ", i+1, "packets, expecting LENGTH ", LENGTH)
      number=packet[i][TCP].chksum-OFFSETB
      if number<0x0:
          number=number+0xFFFF
      print(hex(number))

      if number < 0x1: 
         charnum=('0000')
      elif number < 0x10:
         charnum=str(hex(number))
         charnum='000'+charnum[2]
      elif number < 0x100:
         charnum=str(hex(number))
         charnum='0'+'0'+charnum[2]+charnum[3]
      elif number < 0x1000: 
         charnum=str(hex(number))
         charnum='0'+charnum[2]+charnum[3]+charnum[4]
      else:
         charnum=str(hex(number))
         charnum=charnum[2]+charnum[3]+charnum[4]+charnum[5] 

      if(number == ESCAPE):
         if(PASSTHRU==0):
            PASSTHRU=1 # only write second of two ESCAPE SYNs
            print(PASSTHRU)
         else:
            File_object = open(r"translatedbinaryout","a") #opens text file
            File_object.write(charnum) #good for "a" open
            PASSTHRU=0
         continue
      else:
         if PASSTHRU==1:
            charnum='ffff'
         File_object = open(r"translatedbinaryout","a")
         File_object.write(charnum) 
         PASSTHRU=0
      continue
packed(LENGTH, PASSTHRU)

time.sleep(1)
SIZE=os.path.getsize("translatedbinaryout")
if SIZE+1>>2 > SIZE>>2:
    SIZE=SIZE+1
SIZE=SIZE>>2
print(SIZE)
file_object = open(r"translatedbinaryout", "r")
for i in range(SIZE): 
    Z=file_object.read(2) #python3 reads 2 bytes from the top
    print("This is Z: ", Z)
    V=file_object.read(2) #python3 reads next two bytes
    print("This is V: ", V)

    olookup(V) #V good for little-endian end-points 
    olookup(Z) #Z good for little-endian end-points

#    olookup(Z) #Z good for big-endian end-points
#    olookup(V) #V good for big-endian end-points 



