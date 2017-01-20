#!/usr/bin/env python

import socket
import binascii
from message import Message

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 10910))

t = Message()


t.set_bit(-1, '0820')
t.set_bit(3, {1: '1', 2: '6', 3: '03', 5: '00'})
t.set_bit(7, '10')
t.set_bit(41, '12121212')
t.set_bit(53, '1206000000000000')
t.set_bit(96, '12345678')
# t.bit_map()
print(t.finish())

s.send(binascii.unhexlify(t.finish()))

data = s.recv(4096)
print(binascii.hexlify(data).decode('ascii'))
