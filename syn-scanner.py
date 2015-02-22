#!/usr/bin/python2
# author: deadc0de6
# contact: https://github.com/deadc0de6
#
# syn scanning with scapy and raw sockets
#
# Copyright (C) 2015 deadc0de6
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

import argparse
import datetime
import Queue
from raw import rawsock
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

parser = argparse.ArgumentParser(description='SYN scanner')
parser.add_argument('targets', metavar='targets', type=str, nargs='+', help='the targets')
parser.add_argument('-p', '--port', required=True, help='the ports to scan separated by a comma')
args = parser.parse_args()

dsts = args.targets
ports = args.port.split(',')
TIMEOUT = 3

qin = Queue.Queue()
qout = Queue.Queue()
rs = rawsock(qin, qout, 'tcp')
rs.start()

# send the packets
for p in ports:
  tcp = TCP(sport=RandShort(), dport=int(p), flags="S", seq=RandShort())
  for dst in dsts:
    ip = IP(dst=dst, id=RandShort())
    pkt = ip/tcp
    qin.put((str(pkt), dst, 0))

# receive the packet
cnt = 0
s = datetime.datetime.now()
while cnt < (len(dsts)*len(ports)):
  if (datetime.datetime.now() - s).total_seconds() > TIMEOUT:
    break
  try:
    pkt = qout.get(True, TIMEOUT)
    p = scapy.layers.inet.IP(pkt)
    #print p.summary()
    if not IP in p or not TCP in p:
      #print 'bad protocol'
      continue
    src = p[IP].src
    if not src in dsts:
      #print 'bad source (%s)' % (src)
      continue
    port = p[TCP].sport
    if not str(port) in ports:
      #print 'bad port (%s)' % (port)
      continue
    s = datetime.datetime.now()
    cnt += 1
    flags = p[TCP].flags
    if flags == (SYN|ACK):
      print '%s:%s:open' % (src, port)
    else:
      print '%s:%s:closed' % (src, port)
  except Queue.Empty:
    pass

rs.join()
delta = rs.get_duration()
print 'duration: %s' % (str(delta))

