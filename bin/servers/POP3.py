#!/usr/bin/env python3
from bin.utils import *
import bin.settings
if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler
from bin.packets import POPOKPacket,POPNotOKPacket

# POP3 Server class
class POP3(BaseRequestHandler):
	def SendPacketAndRead(self):
		Packet = POPOKPacket()
		self.request.send(NetworkSendBufferPython2or3(Packet))
		return self.request.recv(1024)

	def handle(self):
		try:
			data = self.SendPacketAndRead()
			if data[0:4] == b'CAPA':
				self.request.send(NetworkSendBufferPython2or3(POPNotOKPacket()))
				data = self.request.recv(1024)
			if data[0:4] == b'AUTH':
				self.request.send(NetworkSendBufferPython2or3(POPNotOKPacket()))
				data = self.request.recv(1024)
			if data[0:4] == b'USER':
				User = data[5:].strip(b"\r\n").decode("latin-1")
				data = self.SendPacketAndRead()
			if data[0:4] == b'PASS':
				Pass = data[5:].strip(b"\r\n").decode("latin-1")

				SaveToDb({
					'module': 'POP3', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': User, 
					'cleartext': Pass, 
					'fullhash': User+":"+Pass,
				})
			self.SendPacketAndRead()
		except Exception:
			pass
