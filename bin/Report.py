import sqlite3
import os

def color(txt, code = 1, modifier = 0):
	if txt.startswith('[*]'):
		settings.Config.PoisonersLogger.warning(txt)
	elif 'Analyze' in txt:
		settings.Config.AnalyzeLogger.warning(txt)

	if os.name == 'nt':
		return txt
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def DbConnect():
    cursor = sqlite3.connect("./Responder.db")
    return cursor

def FingerDbConnect():
    cursor = sqlite3.connect("./tools/RunFinger.db")
    return cursor

def GetResponderData(cursor):
     res = cursor.execute("SELECT * FROM Responder")
     for row in res.fetchall():
         print('{0} : {1}, {2}, {3}, {4}, {5}, {6}, {7}, {8}'.format(row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8]))

def GetResponderUsernamesStatistic(cursor):
     res = cursor.execute("SELECT COUNT(DISTINCT UPPER(user)) FROM Responder")
     for row in res.fetchall():
         print(color('\n[+] In total {0} unique user accounts were captured.'.format(row[0]), code = 2, modifier = 1))

def GetResponderUsernames(cursor):
     res = cursor.execute("SELECT DISTINCT user FROM Responder")
     for row in res.fetchall():
         print('User account: {0}'.format(row[0]))

def GetResponderUsernamesWithDetails(cursor):
     res = cursor.execute("SELECT client, user, module, type, cleartext FROM Responder WHERE UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder) ORDER BY client")
     for row in res.fetchall():
         print('IP: {0} module: {1}:{3}\nuser account: {2}'.format(row[0], row[2], row[1], row[3]))


def GetResponderCompleteHash(cursor):
     res = cursor.execute("SELECT fullhash FROM Responder WHERE UPPER(user) in (SELECT DISTINCT UPPER(user) FROM Responder)")
     for row in res.fetchall():
         print('{0}'.format(row[0]))

def GetUniqueLookups(cursor):
     res = cursor.execute("SELECT * FROM Poisoned WHERE ForName in (SELECT DISTINCT UPPER(ForName) FROM Poisoned) ORDER BY SentToIp, Poisoner")
     for row in res.fetchall():
         print('IP: {0}, Protocol: {1}, Looking for name: {2}'.format(row[2], row[1], row[3]))

def GetUniqueDHCP(cursor):
     res = cursor.execute("SELECT * FROM DHCP WHERE MAC in (SELECT DISTINCT UPPER(MAC) FROM DHCP)")
     for row in res.fetchall():
         print('MAC: {0}, IP: {1}, RequestedIP: {2}'.format(row[1], row[2], row[3]))

def GetRunFinger(cursor):
     res = cursor.execute("SELECT * FROM RunFinger WHERE Host in (SELECT DISTINCT Host FROM RunFinger)")
     for row in res.fetchall():
         print(("{},['{}', Os:'{}', Build:'{}', Domain:'{}', Bootime:'{}', Signing:'{}', Null Session: '{}', RDP:'{}', SMB1:'{}', MSSQL:'{}']".format(row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9], row[10], row[11])))

def GetStatisticUniqueLookups(cursor):
     res = cursor.execute("SELECT COUNT(*) FROM Poisoned WHERE ForName in (SELECT DISTINCT UPPER(ForName) FROM Poisoned)")
     for row in res.fetchall():
         print(color('\n[+] In total {0} unique queries were poisoned.'.format(row[0]), code = 2, modifier = 1))


def SavePoisonersToDb(result):

	for k in [ 'Poisoner', 'SentToIp', 'ForName', 'AnalyzeMode']:
		if not k in result:
			result[k] = ''

def SaveToDb(result):

	for k in [ 'module', 'type', 'client', 'hostname', 'user', 'cleartext', 'hash', 'fullhash' ]:
		if not k in result:
			result[k] = ''

cursor = DbConnect()
print(color("[+] Generating report...\n", code = 3, modifier = 1))
print(color("[+] DHCP Query Poisoned:", code = 2, modifier = 1))
GetUniqueDHCP(cursor)
print(color("\n[+] Unique lookups ordered by IP:", code = 2, modifier = 1))
GetUniqueLookups(cursor)
GetStatisticUniqueLookups(cursor)
print(color("\n[+] Extracting captured usernames:", code = 2, modifier = 1))
GetResponderUsernames(cursor)
print(color("\n[+] Username details:", code = 2, modifier = 1))
GetResponderUsernamesWithDetails(cursor)
GetResponderUsernamesStatistic(cursor)
print(color("\n[+] RunFinger Scanned Hosts:", code = 2, modifier = 1))
cursor.close()
try:
	cursor = FingerDbConnect()
	GetRunFinger(cursor)
except:
	pass
#print('\n')
