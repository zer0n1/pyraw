#!/usr/bin/python2
# author: deadc0de6
# contact: https://github.com/deadc0de6
#
# python raw socket library
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

import socket
import select
import sys
import Queue
import threading
import datetime

class rawsock(threading.Thread):
  TTL = 255
  EPOLL_TIMEOUT = 0.001 # seconds
  QUEUE_TIMEOUT = 1 # second
  PROTOS = ['udp','icmp','tcp']

  DEBUG = False
  READ = True
  WRITE = True
  RCV_BUFSZ = 65535
  TIMEOUT = 3 # seconds

  FLAG_READ = select.EPOLLIN|select.EPOLLHUP|select.EPOLLERR
  FLAG_WRITE = select.EPOLLOUT|select.EPOLLHUP|select.EPOLLERR
  FLAG_RW = select.EPOLLIN|select.EPOLLOUT|select.EPOLLHUP|select.EPOLLERR

  def __init__(self, queuein, queueout, proto, read=True, write=True, debug=False):
    super(rawsock, self).__init__()
    if not proto in self.PROTOS:
      raise Exception('invalid protocol')
    self.queuein = queuein
    self.queueout = queueout
    self.DEBUG = debug
    self.sock = None
    self.poller = None
    self.cnt_out = 0
    self.cnt_in = 0
    self.READ = read
    self.WRITE = write
    self.stopreq = threading.Event()
    self._setup(proto)

  def join(self, timeout=None):
    self.stopreq.set()
    super(rawsock, self).join(timeout)
    return self.cnt_in, self.cnt_out

  def run(self):
    if self.sock == None:
      return self.cnt_in, self.cnt_out
    self.start = datetime.datetime.now()
    while not self.stopreq.isSet(): # or self.queuein.qsize() > 0:
      self._handle_events()
      if (datetime.datetime.now() - self.start).total_seconds() > self.TIMEOUT:
        break
    self.poller.unregister(self.sock.fileno())
    self.poller.close()
    self.sock.close()
    self.stop = datetime.datetime.now()
    return self.cnt_in, self.cnt_out

  def get_counters(self):
    return self.cnt_in, self.cnt_out

  def get_duration(self):
    return self.stop - self.start

  def _setup(self, proto):
    if self.READ and self.WRITE:
      flag = self.FLAG_RW
    elif self.WRITE:
      flag = self.FLAG_WRITE
    elif self.READ:
      flag = self.FLAG_READ
    self._set_socket(proto)
    self._set_poller()
    self.poller.register(self.sock.fileno(), flag)

  def _set_poller(self):
    self.poller = select.epoll()

  def _set_socket(self, proto):
    p = socket.getprotobyname(proto)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, p)
    s.setsockopt(socket.SOL_IP, socket.IP_TTL, self.TTL)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    if self.READ:
      # /proc/sys/net/core/[rw]mem_default
      s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
    if self.WRITE:
      # /proc/sys/net/core/[rw]mem_default
      s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2**30)
    self.sock = s

  def _handle_read(self):
    data = self.sock.recv(self.RCV_BUFSZ)
    if data != None and data != '':
      if self.DEBUG:
        self._err('new packet received ...')
      self.cnt_in += 1
      self.queueout.put(data)

  def _handle_write(self):
    try:
      pkt, tgt, port = self.queuein.get(False) #True, self.QUEUE_TIMEOUT)
      self.cnt_out += 1
      self.sock.sendto(pkt, (tgt, port))
      if self.DEBUG:
        self._err('new packet sent ...')
    except Queue.Empty:
      pass

  def _handle_events(self):
    events = self.poller.poll(self.EPOLL_TIMEOUT)
    for fd, flag in events:
      if fd != self.sock.fileno():
        continue
      if flag&select.POLLIN:
        self._handle_read()
      elif flag&select.POLLOUT:
        if self.queuein.qsize() > 0:
          self._handle_write()
      elif flag&select.POLLHUP:
        self._err('socket hup')
      elif flag&select.POLLERR:
        self._err('socket err')

  def _err(self, string):
    sys.stderr.write('%s\n' % (string))

