#!/usr/bin/env python

'''
SMB Trans2 Stream Decoder + WannaCry ETERNALBLUE payload extractor
Copyright (C) 2017 Tillmann Werner
'''

import sys
import struct
from smbtrans2 import SMBTrans2


def main():
	indata = open(sys.argv[1], 'rb').read()

	d = SMBTrans2()

	streams = d.decode(indata)

	for treeid in streams.keys():
		if len(streams[treeid]) > 0:
			open(sys.argv[1] + '.trans2stream.' + str(treeid), 'wb').write(streams[treeid])
			print "decoded SMB stream dumped to %s" % sys.argv[1] + '.trans2stream.' + str(treeid)

			# read xor key from fixed offset and decrypt the stream
			key = streams[treeid][0x800:0x800+4]
			dec = ''
			for i, b in enumerate(streams[treeid]):
				dec += chr(ord(b) ^ ord(key[i%4]))

			open(sys.argv[1] + '.trans2stream.' + str(treeid) + '.dec', 'wb').write(dec)
			print "decrypted SMB stream dumped to %s" % sys.argv[1] + '.trans2stream.' + str(treeid) + '.dec'

			# payload starts at offset 0xe0a8
			open(sys.argv[1] + '.trans2stream.' + str(treeid) + '.dec.payload', 'wb').write(dec[0xe0a8:])
			print "extracted payload dumped to %s" % sys.argv[1] + '.trans2stream.' + str(treeid) + '.dec.payload'

	return 0

if __name__ == '__main__':
	main()
