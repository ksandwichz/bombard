#!/usr/bin/python
# -*- coding: utf-8 -*-
#####################################################
### This is a very simple DNS server for Bombard. ###
### The job is to accept a A record request and   ###
### return a record if it is in the simple config ###
### file. ....................  ###
#####################################################
# Nov 30, 2013 ######################################
#####################################################

import socket
import sys
import os
import signal
import struct

PORT = 53

ip = raw_input('What IP should we return: ')
ip = ip.split('.')

# Convert this to network byte order

ip = struct.pack('!BBBB', int(ip[0]), int(ip[1]), int(ip[2]),
                 int(ip[3]))


class dnsRecord(object):

    def __init__(
        self,
        tid,
        name,
        ip,
        ):

        # A response packet - in order of fields you find in a DNS A record reply. Note - I am using wireshark to find this. All fields except record 2 bytes.

        self.tid = tid  # This needs to match the transaction id that we recieved in the query.
        self.flags = '\x81\x80'  # Return a binary mask of 16 bits .. this has response flag, recursion desired, and recursion available set to 1
        self.qstn = '\x00\x01'  # This sets question to 1
        self.ansr = '\x00\x01'  # We are returning only one answer, so set this to one. It can be changed if you return more than one.
        self.auth = '\x00\x00'  # No auth RR
        self.addn = '\x00\x00'  # No addn RR
        self.name = name  # This is the same name we recieved the query for.
        self.type_ = '\x00\x01'  # Type is A record for this exercise
        self.clss = '\x00\x01'  # Class IN

        # Here we add the answer which is the IP address we want to return. 192.168.1.1 !

        self.answer = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\xFF\x00\x04"
        self.ip = ip  # 192.168.1.1...."\xc0\xa6\x01\x01"

    def reply(self):
        return self.tid + self.flags + self.qstn + self.ansr \
            + self.auth + self.addn + self.name + self.type_ \
            + self.clss + self.answer + self.ip


class dnsQuery(object):

    def __init__(self, data):

        # in order of position in packet - each field is 2 bytes except the name which is variable. need to make that section look cleaner.

        self.tid = data[:2]
        self.flags = data[2:4]
        self.qstn = data[4:6]
        self.ansr = data[6:8]
        self.auth = data[8:10]
        self.addn = data[10:12]

        # Calculate variable length of name field.

        name_len = len(data) - 16
        self.strt_mask = '!' + 'B' * name_len
        self.name = data[12:name_len + 12]
        self.type_ = data[len(data) - 4:len(data) - 2]
        self.clss = data[len(data) - 2:len(data)]


# Make a socket and bind it to all IPs on port 53.

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', PORT))
counter = 0

while True:
    counter = counter + 1
    (data, addr) = s.recvfrom(1024)
    q = dnsQuery(data)
    r = dnsRecord(q.tid, q.name, ip)
    s.sendto(r.reply(), addr)

