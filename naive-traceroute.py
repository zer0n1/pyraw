#!/usr/bin/python2
# author: deadc0de6
# contact: https://github.com/deadc0de6
#
# naive traceroute with ICMP/UDP/TCP
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
import Queue
import random
import string
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from raw import rawsock

def out(string, crlf=True):
  sys.stdout.write('%s%s' % (string, '\n' if crlf else ''))
  sys.stdout.flush()

def get_packet(dst, ttl, proto, port):
  pkt = None
  if proto == 'icmp':
    pkt = IP(dst=dst, id=RandShort(), ttl=ttl)/ICMP(id=RandShort(), seq=RandShort())
  elif proto == 'tcp':
    pkt = IP(dst=dst, id=RandShort(), ttl=ttl)/TCP(sport=RandShort(), dport=port, flags="S", seq=RandShort())
  elif proto == 'udp':
    pld = ''.join(random.choice(string.letters) for i in range(32))
    pkt = IP(dst=dst, id=RandShort(), ttl=ttl)/UDP(sport=RandShort(), dport=port)/Raw(pld)
  return pkt

if os.geteuid() != 0:
  sys.stderr.write('get r00t !\n')
  sys.exit(0)

parser = argparse.ArgumentParser(description='ICMP traceroute')
parser.add_argument('targets', metavar='targets', type=str, nargs='+',
  help='the targets')
parser.add_argument('--maxttl', default=30, type=int)
parser.add_argument('--proto', choices=['icmp', 'udp', 'tcp'], default='icmp')
parser.add_argument('--port', default=33434, type=int)
args = parser.parse_args()

dsts = args.targets
MAXTTL = args.maxttl
PORT = args.port
TIMEOUT = 3
PROTO = args.proto

# set the queues
qin = Queue.Queue()
qout = Queue.Queue()
# set the rawsock
rs = rawsock(qin, qout, 'icmp')
# start the thread
rs.start()

for dst in dsts:
  out('tracerouting %s with proto %s' % (dst, PROTO))
  reached = False
  pong = False
  # send packet
  for ttl in range(1, MAXTTL+1):
    pkt = get_packet(dst, ttl, PROTO, PORT)
    #print pkt.summary()
    out('@%i -> ' % (ttl), crlf=False)
    stuff = (str(pkt), dst, PORT)
    qin.put(stuff)

    # receive packet
    s = datetime.datetime.now()
    while (datetime.datetime.now() - s).total_seconds() < TIMEOUT:
      try:
        pkt = qout.get(True, TIMEOUT)
        p = scapy.layers.inet.IP(pkt)
        if not IP in p or not ICMP in p:
          out('...', crlf=False)
          continue
        src = p[IP].src
        if src == dst:
          out('%s' % (dst), crlf=False)
          reached = True
          break
        if p[ICMP].type != 11 and p[ICMP].code != 0:
          out('...', crlf=False)
          continue
        out('%s' % (src), crlf=False)
        break
      except Queue.Empty:
        out('...', crlf=False)
    out('', crlf=True)
    if reached:
      break

# quit
rcv, snd = rs.join()
out('received: %i | sent: %i' % (rcv, snd))

delta = rs.get_duration()
out('duration: %s' % (str(delta)))

