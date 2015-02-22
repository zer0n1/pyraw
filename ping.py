#!/usr/bin/python2
# author: deadc0de6
# contact: https://github.com/deadc0de6
#
# ICMP echo request with scapy and raw socket
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

import os
import datetime
import argparse
import logging
import Queue
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from raw import rawsock

if os.geteuid() != 0:
  sys.stderr.write('get r00t !\n')
  sys.exit(0)

parser = argparse.ArgumentParser(description='pinger')
parser.add_argument('targets', metavar='targets', type=str, nargs='+',
  help='the targets')
parser.add_argument('-c', '--nbprobe', default=3, type=int,
  help='number of probe to send to each target')
args = parser.parse_args()
dsts = args.targets
TIMEOUT = 3

# set the queues
qin = Queue.Queue()
qout = Queue.Queue()
# set the rawsock
rs = rawsock(qin, qout, 'icmp')
# start the thread
rs.start()

# send packet
for dst in dsts:
  print 'pinging %s with %i probe(s)' % (','.join(dsts), args.nbprobe)
  for i in range(args.nbprobe):
    pkt = IP(dst=dst, id=RandShort())/ICMP(id=RandShort(), seq=RandShort())
    stuff = (str(pkt), dst, 0)
    qin.put(stuff)

# receive packet
s = datetime.datetime.now()
cnt = 0
while cnt < (len(dsts)*args.nbprobe):
  if (datetime.datetime.now() - s).total_seconds() > TIMEOUT:
    break
  try:
    pkt = qout.get(True, TIMEOUT)
    p = scapy.layers.inet.IP(pkt)
    if not IP in p or not ICMP in p:
      continue
    src = p[IP].src
    if not src in dsts:
      continue
    if p[ICMP].type != 0:
      continue
    print 'echo-reply received by %s' % (src)
    cnt += 1
  except Queue.Empty:
    pass

rs.join()
delta = rs.get_duration()
print 'duration: %s' % (str(delta))

