# p2p-ipv4-offset-python3

P2P-IPV4-OFFSET-PYTHON3 is a Python3.9 or later prototype build of the prior P2P-IPV4-OFFSET proof-of-concept. 
An encrypted file is transferred between two IP end-points, two bytes at a time, in successive 16-bit TCPIP SYN 
TCPcksums. No network connection is established, only SYNs are sent "under the radar" of connection-oriented 
surveillance.

A five packet preamble helps RECEIVER derive a two byte OFFSET that will transform bytes received back to the 
intended bytes sent. An ESCAPE packet's TCPcksum at each end is also derived. During file transfer an ESCAPE 
SYN packet precedes sending two bytes of 'ffff', which actually might be received as a lone '0000' otherwise. 
Also, two ESCAPE SYN packets received together are interpreted by RECEIVER as only one ESCAPE SYN packet.

RECEIVER's decryption success confirms intended delivery. Decryption warnings reported for odd-length gpg files
are prevented by first wrapping the file in zip and then unzipping. When file transfer has completed RECEIVER
examines the accumulated bintranslatedbinaryout file:

wc bin*         --does this indicate any dropped packets? Expect almost all IP end-points to be clear channels.

gpg -d bin*     --if length is correct but decryption fails or gives a warning anyway, then try:

unzip bin*      --if unzip fails, then try:

cat bin*        --displays plaintext when SENDER decides the best option, or the only option, is plaintext

hexdump bin*    --displays a binary file when cat bin* is not plaintext ASCII characters

A SENDER at either end must know their RECEIVER's IPv4 network address at the other end. Both ends require
root access to their SSH server (or be intra-LAN) for python3 nreceive.py and python3 nsendit.py IP4DEST FILE.
