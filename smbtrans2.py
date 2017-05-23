#!/usr/bin/env python

'''
SMB Trans2 Stream Decoder
Copyright (C) 2017 Tillmann Werner
'''

import sys
import struct

class SMBTrans2:
	def __init__(self, debug=False):
		self.offset = 0
		self.streams = {}
		self.debug = debug
		return

	def __log__(self, msg, args):
		if self.debug != True: return
		print msg % args
		return


	def decode(self, indata, offset=0):
		self.offset = offset

		while self.offset + 14 < len(indata):
			nbhdr, = struct.unpack('>I', indata[self.offset:self.offset+4])
			nblen = nbhdr & 0xffffff

			smbcomp, smbcmd, smbstatus, smbflags = struct.unpack('<IbIb', indata[self.offset+4:self.offset+14])

			if smbcomp != 0x424d53ff:
				raise IOError("unimplemented SMB component")
				break

			if smbcmd == 0x32:
				if smbflags & 0x80 == 0:
					# get Tree ID from SMB header and make sure a stream exists in the dict
					treeid = struct.unpack('<H', indata[self.offset+28:self.offset+30])[0]
					if treeid not in self.streams: self.streams[treeid] = ''

					trans2 = indata[self.offset+4+32:self.offset+4+32+34]
					pc, po, dc, do, sc, res, cmd = struct.unpack('<HHHHbbH', trans2[19:19+12])
					payload = indata[self.offset+4+32+34+12:self.offset+4+32+34+12+dc]

					self.streams[treeid] += payload
				else:
					self.__log__("%5d  Trans2 Response (%x bytes)", (self.offset, nblen))
			elif smbcmd == 0x72: self.__log__("%5x  Netotiate Protocol %s (%x bytes)", (self.offset, "Request" if smbflags & 0x80 == 0 else "Response", nblen))
			elif smbcmd == 0x73: self.__log__("%5x  Session Setup AndX %s (%x bytes)", (self.offset, "Request" if smbflags & 0x80 == 0 else "Response", nblen))
			elif smbcmd == 0x75: self.__log__("%5x  Tree Connect %s (%x bytes)", (self.offset, "Request" if smbflags & 0x80 == 0 else "Response", nblen))
			else:
				raise IOError("unimplemented SMB command")
				break

			self.offset += 4 + nblen

		return self.streams

	def get_tree_ids(self):
		return self.sreams.keys()

	def get_stream(self, treeid):
		return self.streams[treeid]
