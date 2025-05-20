import ipaddress
import socket
import sys
import os
import os.path
import argparse
import textwrap
import re
import threading
from datetime import datetime
from binascii import hexlify
from typing import Optional, List

from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES
import ldap3
from colorama import Fore, Style, init
from Cryptodome.Hash import MD4
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.structure import Structure
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key


def print_info(msg: str):
    print(Fore.YELLOW + Style.BRIGHT + msg + Style.RESET_ALL)

def print_success(msg: str):
    print(Fore.GREEN + Style.BRIGHT + msg + Style.RESET_ALL)

def print_error(msg: str):
    print(Fore.RED + Style.BRIGHT + msg + Style.RESET_ALL)


class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version', '<H'),
        ('Reserved', '<H'),
        ('Length', '<L'),
        ('CurrentPasswordOffset', '<H'),
        ('PreviousPasswordOffset', '<H'),
        ('QueryPasswordIntervalOffset', '<H'),
        ('UnchangedPasswordIntervalOffset', '<H'),
        ('CurrentPassword', ':'),
        ('PreviousPassword', ':'),
        ('QueryPasswordInterval', ':'),
        ('UnchangedPasswordInterval', ':'),
    )

    def __init__(self, data=None):
        super().__init__(data=data)

    def fromString(self, data):
        super().fromString(data)
        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']
        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]
        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]


class LDAPSearch:
    def __init__(self):
        self.args = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.hash: Optional[str] = None
        self.hostname: Optional[str] = None
        self.server: Optional[Server] = None
        self.conn: Optional[Connection] = None
        self.dir_name: Optional[str] = None
        self.name_context: Optional[str] = None
        self.dom_1: Optional[str] = None
        self.dc_val: Optional[int] = None
        self.long_dc: Optional[str] = None
        self.domain: Optional[str] = None
        self.t1: Optional[datetime] = None
        self.t2: Optional[datetime] = None
        self.subnet: Optional[str] = None

    def banner(self):
        print_info("")
        print(r'                   __    ____  ___    ____  ____')
        print(r'   ____ ___  _____/ /   / __ \/   |  / __ \/ __ \__  ______ ___  ____')
        print(r'  / __ `__ \/ ___/ /   / / / / /| | / /_/ / / / / / / / __ `__ \/ __ \ ')
        print(r' / / / / / (__  ) /___/ /_/ / ___ |/ ____/ /_/ / /_/ / / / / / / /_/ /')
        print(r'/_/ /_/ /_/____/_____/_____/_/  |_/_/   /_____\/__,_/_/ /_/ /_/ .___/')
        print('                   Active Directory LDAP Enumerator          /_/ v1.1 Release')
        print("                     Another Project by TheMayor \n" + Style.RESET_ALL)

    def arg_handler(self):
        parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent(
                '''Anonymous Bind: python3 msldapdump.py -a --dc 192.168.1.79\n\nAuthenticated Bind: python3 msldapdump.py --dc 192.168.1.79 --user testuser --password Password123!\n\nNTLM Authenticated Bind: python3 msldapdump.py --dc 192.168.1.79 --user testuser --ntlm <hash>\n''')
        )
        target = parser.add_argument_group('Target')
        target.add_argument('-d', '--dc', required=True, help='Domain controller IP.')
        target.add_argument('-sn', '--subnet', help='Quick portscan for DCs (ex. 192.168.1.0; /24 only).')
        anon = parser.add_argument_group('Anonymous Bind')
        anon.add_argument('-a', '--anon', action='store_true', help='Anonymous bind checks only.')
        auth = parser.add_argument_group('Authenticated Bind')
        auth.add_argument('-u', '--user', help='Username to authenticate with.')
        auth.add_argument('-p', '--password', help='Password to authenticate with.')
        auth.add_argument('-n', '--ntlm', help='NTLM hash to use in place of a password.')
        auth.add_argument('-dn', '--domain', help='Domain name, if unknown.')
        self.args = parser.parse_args()
        self.hostname = self.args.dc
        self.username = self.args.user
        self.password = self.args.password
        self.hash = self.args.ntlm
        self.subnet = self.args.subnet
        if self.args.domain:
            self.domain = self.args.domain

    def portscan(self):
        if not self.subnet:
            print_error("No subnet provided for portscan.")
            return
        socket.setdefaulttimeout(0.05)
        check_ports = [389, 636, 3269]
        print_info(f'[info] Checking for possible domain controllers in the {self.subnet}/24 subnet.')

        def scan_host(host):
            for port in check_ports:
                try:
                    ip_addr = self.subnet[:self.subnet.rfind('.') + 1] + str(host)
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.connect((ip_addr, port))
                        try:
                            host_resolve = socket.gethostbyaddr(ip_addr)[0]
                            print_success(f"[+] Possible Domain Controller found at {ip_addr} - {host_resolve}.")
                        except Exception:
                            print_success(f"[+] Possible Domain Controller found at {ip_addr}.")
                        return
                except (ConnectionRefusedError, AttributeError, OSError):
                    pass

        threads = []
        for host in range(1, 255):
            t = threading.Thread(target=scan_host, args=(host,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        print_info("\n[info] Scan complete. Use identified IPs for further enumeration.")

    def _get_server(self, use_ssl=True) -> Server:
        try:
            if use_ssl:
                server_val = f'ldaps://{self.hostname}:636'
                return Server(server_val, port=636, use_ssl=True, get_info=ALL)
            else:
                return Server(self.hostname, port=389, use_ssl=False, get_info=ALL)
        except Exception as e:
            print_error(f"Error creating LDAP server object: {e}")
            raise

    def _get_domain_context(self) -> None:
        # Extract domain context from server info file
        try:
            with open(f"{self.hostname}.ldapdump.txt", 'r') as f:
                for line in f:
                    if line.startswith("    DC="):
                        self.name_context = line.strip()
                        self.long_dc = self.name_context
                        self.dc_val = self.name_context.count('DC=')
                        self.name_context = self.name_context.replace("DC=", "").replace(",", ".")
                        if "ForestDnsZones" in self.name_context or "DomainDnsZones" in self.name_context:
                            continue
                        break
            self.dir_name = self.name_context
            if not self.domain:
                self.domain = self.name_context
        except Exception as e:
            print_error(f"Error extracting domain context: {e}")
            raise

    def _create_output_dir(self):
        try:
            if not os.path.exists(self.dir_name):
                os.mkdir(self.dir_name)
            src = f"{self.hostname}.ldapdump.txt"
            dst = f"{self.dir_name}\\{self.domain}.ldapdump.txt"
            if os.path.exists(dst):
                os.remove(dst)
            os.rename(src, dst)
        except Exception as e:
            print_error(f"Error creating output directory: {e}")

    def anonymous_bind(self):
        try:
            self.t1 = datetime.now()
            try:
                self.server = self._get_server(use_ssl=True)
            except Exception:
                self.server = self._get_server(use_ssl=False)
            self.conn = Connection(self.server, auto_bind=True)
            with open(f"{self.hostname}.ldapdump.txt", 'w') as f:
                f.write(str(self.server.info))
            self._get_domain_context()
            print_success(f"[success] Possible domain name found - {self.name_context}")
            print_info('[info] Attempting to gather additional information about the domain.')
            # Additional info extraction can be added here
            print_info(f'\n[info] All set for now. Come back with credentials to dump additional domain information. Full raw output saved as {self.hostname}.ldapdump.txt\n')
            self.t2 = datetime.now()
            print_info(f"LDAP enumeration completed in {self.t2 - self.t1}.")
        except (ipaddress.AddressValueError, socket.herror):
            print_error("Invalid IP Address or unable to contact host. Please try again.")
        except socket.timeout:
            print_error("Timeout while trying to contact the host. Please try again.")
        except Exception as e:
            print_error(f"[error] - {e}")

    def authenticated_bind(self):
        self.t1 = datetime.now()
        try:
            try:
                self.server = self._get_server(use_ssl=True)
            except Exception:
                self.server = self._get_server(use_ssl=False)
            self.conn = Connection(self.server, auto_bind=True)
            with open(f"{self.hostname}.ldapdump.txt", 'w') as f:
                f.write(str(self.server.info))
            self._get_domain_context()
            self._create_output_dir()
            print_success(f"[success] Possible domain name found - {self.name_context}")
            self.dom_1 = self.long_dc
            # Try UPN format first, then DOMAIN\user
            user_upn = f"{self.username}@{self.domain}"
            try:
                self.conn = Connection(self.server, user=user_upn, password=self.password, auto_bind=True)
                self.conn.bind()
            except ldap3.core.exceptions.LDAPBindError as e:
                print_info(f"UPN bind failed: {e}. Trying DOMAIN\\user format...")
                dom_name = self.domain.split(".", 1)[0]
                user_sam = f"{dom_name}\\{self.username}"
                try:
                    self.conn = Connection(self.server, user=user_sam, password=self.password, auto_bind=True)
                    self.conn.bind()
                except ldap3.core.exceptions.LDAPBindError as e2:
                    print_error(f"Both UPN and DOMAIN\\user bind failed: {e2}")
                    return
            print_success(f"[success] Connected to {self.hostname}.")
            self.enumerate_all()
        except (ipaddress.AddressValueError, socket.herror):
            print_error("Invalid IP Address or unable to contact host. Please try again.")
        except socket.timeout:
            print_error("Timeout while trying to contact the host. Please try again.")
        except Exception as e:
            print_error(f"[error] - {e}")

    def ntlm_bind(self):
        self.t1 = datetime.now()
        try:
            try:
                self.server = self._get_server(use_ssl=True)
            except Exception:
                self.server = self._get_server(use_ssl=False)
            self.conn = Connection(self.server, auto_bind=True)
            with open(f"{self.hostname}.ldapdump.txt", 'w') as f:
                f.write(str(self.server.info))
            self._get_domain_context()
            self._create_output_dir()
            print_success(f"[success] Possible domain name found - {self.name_context}")
            self.dom_1 = self.long_dc
            # Try UPN format first, then DOMAIN\user
            user_upn = f"{self.username}@{self.domain}"
            try:
                self.conn = Connection(self.server, user=user_upn, password=self.hash, auto_bind=True, authentication=NTLM)
                self.conn.bind()
            except ldap3.core.exceptions.LDAPBindError as e:
                print_info(f"NTLM UPN bind failed: {e}. Trying DOMAIN\\user format...")
                dom_name = self.domain.split(".", 1)[0]
                user_sam = f"{dom_name}\\{self.username}"
                try:
                    self.conn = Connection(self.server, user=user_sam, password=self.hash, auto_bind=True, authentication=NTLM)
                    self.conn.bind()
                except ldap3.core.exceptions.LDAPBindError as e2:
                    print_error(f"Both NTLM UPN and DOMAIN\\user bind failed. This is usually caused by an incorrect username format, hash, or server configuration. Full error: {e2}")
                    return
            print_success(f"[success] Connected to {self.hostname}.")
            self.enumerate_all()
        except (ipaddress.AddressValueError, socket.herror):
            print_error("Invalid IP Address or unable to contact host. Please try again.")
        except socket.timeout:
            print_error("Timeout while trying to contact the host. Please try again.")
        except Exception as e:
            print_error(f"[error] - {e}")

    def enumerate_all(self):
        # Call all enumeration methods in order
        self.domain_recon()
        self.gmsa_accounts()
        self.laps()
        self.search_users()
        self.search_pass_expire()
        self.search_groups()
        self.admin_accounts()
        self.kerberoast_accounts()
        self.aspreproast_accounts()
        self.unconstrained_search()
        self.constrainted_search()
        self.computer_search()
        self.ad_search()
        self.trusted_domains()
        self.server_search()
        self.deprecated_os()
        self.mssql_search()
        self.exchange_search()
        self.gpo_search()
        self.admin_count_search()
        self.find_fields()

    def domain_recon(self):
        print_info("\n[info] Let's dump some domain information quick.")
        # Quick check on current user's permissions in the domain
        print('\n' + '-'*31 + 'Domain Enumeration' + '-'*31)
        self.conn.search(
            f'{self.dom_1}', f'(sAMAccountName={self.username})', attributes=ldap3.ALL_ATTRIBUTES)
        for entry in self.conn.entries:
            username = entry.sAMAccountName
            print(f"Current User: {username}")
        try:
            groups = self.conn.entries[0]['memberOf']
            print("Group Membership(s):")
            for entry in groups:
                entry1 = str(entry)
                remove_cn = entry1.replace('CN=', '')
                group_name = remove_cn.split(',')
                group = str(group_name[0])
                print(group)
        except Exception:
            pass
        self.conn.search(f'{self.dom_1}', '(objectclass=*)',
                         attributes=['ms-DS-MachineAccountQuota'])
        quota_val = self.conn.entries[0]['ms-DS-MachineAccountQuota']
        self.conn.search(f'{self.dom_1}', '(objectClass=domain)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries[0]
        entries_val = str(entries_val)
        for entries in self.conn.entries:
            if entries.pwdProperties == 1:
                pass_complexity = "Enabled"
            elif entries.pwdProperties == 0:
                pass_complexity = "Disabled"
            print(f"\nDomain Info:\nDomain SID: {entries.objectSid}\nDomain Created Date: {entries.CreationTime}\nms-DS-MachineAccountQuota: {quota_val}\n\nPassword Policy:\nLockout Threshold: {entries.lockoutThreshold}\nLockout Duration: {entries.lockoutDuration}\nMax Password Age: {entries.maxPwdAge}\nMinimum Password Length: {entries.minPwdLength}\nPassword Complexity: {pass_complexity}")
        return self.conn.entries

    def gmsa_accounts(self):
        gmsa_accounts = []
        try:
            print('\n' + '-'*25 + 'Group Managed Service Accounts' + '-'*26 + '\n')
            self.conn.search(f'{self.dom_1}', '(&(ObjectClass=msDS-GroupManagedServiceAccount))', attributes=['sAMAccountName', 'msDS-ManagedPassword', 'msDS-GroupMSAMembership'])
            gmsa_val = self.conn.entries
            for accounts in gmsa_val:
                gmsa_accounts.append(accounts.sAMAccountName)
            for account_name in gmsa_accounts:
                account_name = str(account_name)
                # print(account_name)
            for entry in self.conn.entries:
                    sam = entry['sAMAccountName'].value
                    # print('Users or groups who can read password for '+sam+':')
                    for dacl in SR_SECURITY_DESCRIPTOR(data=entry['msDS-GroupMSAMembership'].raw_values[0])['Dacl']['Data']:
                        self.conn.search(f'{self.dom_1}', '(&(objectSID='+dacl['Ace']['Sid'].formatCanonical()+'))', attributes=['sAMAccountName'])
                        
                        # Added this check to prevent an error from occuring when there are no results returned
                        if len(self.conn.entries) != 0:
                            print('Users or groups who can read password for '+sam+':')
                            print(' > ' + self.conn.entries[0]['sAMAccountName'].value)

                    if 'msDS-ManagedPassword' in entry and entry['msDS-ManagedPassword']:
                        data = entry['msDS-ManagedPassword'].raw_values[0]
                        blob = MSDS_MANAGEDPASSWORD_BLOB()
                        blob.fromString(data)
                        currentPassword = blob['CurrentPassword'][:-2]

                        # Compute ntlm key
                        ntlm_hash = MD4.new ()
                        ntlm_hash.update (currentPassword)
                        passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
                        print(f'-- Hashes for {sam} --')
                        userpass = sam + ':aad3b435b51404eeaad3b435b51404ee:' + passwd
                        print(userpass)

                        # Compute aes keys
                        password = currentPassword.decode('utf-16-le', 'replace').encode('utf-8')
                        # print(password)
                        salt = '%shost%s.%s' % (self.args.domain.upper(), sam[:-1].lower(), self.args.domain.lower())
                        aes_128_hash = hexlify(string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents)
                        aes_256_hash = hexlify(string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents)
                        print('%s:aes256-cts-hmac-sha1-96:%s' % (sam, aes_256_hash.decode('utf-8')))
                        print('%s:aes128-cts-hmac-sha1-96:%s' % (sam, aes_128_hash.decode('utf-8')))
        except Exception:
            pass

    def laps(self):
        # Check for LAPS passwords accessible to the current user
        print('\n' + '-'*33 + 'LAPS Passwords' + '-'*33 +
              '\n This relies on the current user having permissions to read LAPS passwords\n')
        try:
            self.conn.search(
                f'{self.dom_1}', '(ms-MCS-AdmPwd=*)', attributes=['ms-Mcs-AdmPwd'])
            entries_val = self.conn.entries
            entries_val = str(entries_val)
            for entry in self.conn.entries:
                print(str(entry))
            if os.path.exists(f"{self.dir_name}\\{self.domain}.laps.txt"):
                os.remove(f"{self.dir_name}\\{self.domain}.laps.txt")
            with open(f"{self.dir_name}\\{self.domain}.laps.txt", 'w') as f:
                f.write(entries_val)
                f.close
        except Exception:
            pass

    def search_users(self):
        # Search domain users
        self.conn.search(
            f'{self.dom_1}', '(&(objectclass=person)(objectCategory=Person))', search_scope=SUBTREE, attributes=ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*38 + 'Users' + '-'*37 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.users.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.users.txt")
        with open(f"{self.dir_name}\\{self.domain}.users.txt", 'w') as f:
            f.write(entries_val)
            f.close
        for users in self.conn.entries:
            try:
                print(users.sAMAccountName)
            except Exception:
                pass

    def search_pass_expire(self):
        # Search for users where the password attribute is set to not expire

        self.conn.search(
            f'{self.dom_1}', '(&(objectclass=user)(objectCategory=Person)(userAccountControl:1.2.840.113556.1.4.803:=65536))', attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*24 + 'Users With Non-Expiring Passwords' + '-'*23 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.pass_never_expires.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.pass_never_expires.txt")
        with open(f"{self.dir_name}\\{self.domain}.pass_never_expires.txt", 'w') as f:
            f.write(entries_val)
            f.close
        try:
            for users in self.conn.entries:
                print(users.sAMAccountName)
        except Exception:
            pass

    def search_groups(self):
        # Query LDAP for groups
        self.conn.search(f'{self.dom_1}', '(objectclass=group)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*37 + 'Groups' + '-'*37 + '\n')
        entries_val = str(entries_val)
        for group in self.conn.entries:
            print(group.sAMAccountName)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.groups.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.groups.txt")
        with open(f"{self.dir_name}\\{self.domain}.groups.txt", 'w') as f:
            f.write(entries_val)
            f.close

    def admin_accounts(self):
        try:
            admin_users = []
            self.conn.search(f'{self.dom_1}', '(&(objectclass=group)(CN=*admin*))',
                            attributes=['member'])
            entries_val = str(self.conn.entries)
            self.conn.search(f'{self.dom_1}', '(&(objectclass=group)(CN=*operator*))',
                            attributes=['member'])
            print('\n' + '-'*30 + 'Admin Level Users' + '-'*30 + '\n')
            entries_val1 = str(self.conn.entries[0])
            if os.path.exists(f"{self.dir_name}\\{self.domain}.adminusers.txt"):
                os.remove(f"{self.dir_name}\\{self.domain}.adminusers.txt")
            with open(f"{self.dir_name}\\{self.domain}.adminusers.txt", 'w') as f:
                f.write(entries_val)
                f.write(entries_val1)
                f.close()
            with open(f"{self.dir_name}\\{self.domain}.adminusers.txt", 'r+') as f:
                admin_val = 0
                for line in f:
                    if line.startswith('    member: '):
                        admin_name = line.strip()
                        admin_name = admin_name.replace('member: ', '')
                        if admin_name not in admin_users:
                            self.conn.search(admin_name, '(objectClass=user)', attributes=['sAMAccountName'])
                            for entry in self.conn.entries:
                                sam_name = self.conn.entries[0].sAMAccountName
                                print(sam_name)
                            admin_users.append(admin_name)
                            admin_val += 1
                        else:
                            pass
                        if admin_val >= 25:
                            print_info(f'\n[info] Truncating results at 25. Check {self.domain}.adminusers.txt for full details.')
                            break
                f.close()
        except Exception as e:
            print(e)

    def kerberoast_accounts(self):
        # Query LDAP for Kerberoastable users - searching for SPNs where user is a normal user and account is not disabled
        self.conn.search(f'{self.dom_1}', '(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
                         attributes=[ldap3.ALL_ATTRIBUTES])
        entries_val = self.conn.entries
        print('\n' + '-'*30 + 'Kerberoastable Users' + '-'*30 + '\n')
        entries_val = str(entries_val)
        for kerb_users in self.conn.entries:
            print(kerb_users.sAMAccountName)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.kerberoast.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.kerberoast.txt")
        with open(f"{self.dir_name}\\{self.domain}.kerberoast.txt", 'w') as f:
            f.write(entries_val)
            f.close()

    def aspreproast_accounts(self):
        # Query LDAP for ASREPRoastable Users
        self.conn.search(f'{self.dom_1}', '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))', attributes=[
            'sAMAccountName'])
        entries_val = self.conn.entries
        print('\n' + '-'*30 + 'ASREPRoastable Users' + '-'*30 + '\n')
        entries_val = str(entries_val)
        for asrep_users in self.conn.entries:
            print(asrep_users.sAMAccountName)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.asreproast.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.asreproast.txt")
        with open(f"{self.dir_name}\\{self.domain}.asreproast.txt", 'w') as f:
            f.write(entries_val)
            f.close()

    def unconstrained_search(self):
        # Query LDAP for Unconstrained Delegation Rights
        self.conn.search(f'{self.dom_1}', "(&(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*28 + 'Unconstrained Delegations' + '-'*27 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.unconstrained.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.unconstrained.txt")
        with open(f"{self.dir_name}\\{self.domain}.unconstrained.txt", 'w') as f:
            f.write(entries_val)
            f.close()
        with open(f"{self.dir_name}\\{self.domain}.unconstrained.txt", 'r+') as f:
            uncon_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    uncon_name = line.strip()
                    uncon_name = uncon_name.replace('sAMAccountName: ', '')
                    print(f'{uncon_name}')
                    uncon_val += 1
                    if uncon_val >= 25:
                        print_info(f'\n[info] Truncating results at 25. Check {self.domain}.unconstrained.txt for full details.')
                        break
            f.close()

    def constrainted_search(self):
        # Query LDAP for Constrained Delegation Rights
        self.conn.search(f'{self.dom_1}', "(msDS-AllowedToDelegateTo=*)",
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*29 + 'Constrained Delegations' + '-'*28 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.constrained.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.constrained.txt")
        with open(f"{self.dir_name}\\{self.domain}.constrained.txt", 'w') as f:
            f.write(entries_val)
            f.close()
        with open(f"{self.dir_name}\\{self.domain}.constrained.txt", 'r+') as f:
            con_val = 0
            for line in f:
                if line.startswith('    cn: '):
                    constrained_name = line.strip()
                    constrained_name = constrained_name.replace('cn: ', '')
                if line.startswith('    msDS-AllowedToDelegateTo: '):
                    del_to = line.strip()
                    del_to = del_to.replace('msDS-AllowedToDelegateTo: ', '')
                    print(
                        f'{constrained_name} has constrained delegation rights to {del_to}')
                    con_val += 1
                    if con_val >= 25:
                        print_info(f'\n[info] Truncating results at 25. Check {self.domain}.constrained.txt for full details.')
                        break
            f.close()

    def computer_search(self):
        # Query LDAP for computer accounts
        self.conn.search(f'{self.dom_1}', '(&(objectClass=computer)(!(objectclass=msDS-ManagedServiceAccount)))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*36 + 'Computers' + '-'*35 + '\n')
        entries_val = str(entries_val)
        for comp_account in self.conn.entries:
            print(f"{comp_account.name}")
        if os.path.exists(f"{self.dir_name}\\{self.domain}.computers.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.computers.txt")
        with open(f"{self.dir_name}\\{self.domain}.computers.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        if sys.platform.startswith('win32'):
            # Runs a check to see if the current system is Windows. In place until the Linux DNS resolution on multiple adapters issue is resolved.
            print_info("\n[info] Let's try to resolve hostnames to IP addresses. This may take some time depending on the number of computers...\n")
            with open(f"{self.dir_name}\\{self.domain}.computers.txt", 'r+') as f:
                comp_val1 = 0
                for line in f:
                    if line.startswith('    sAMAccountName: '):
                        comp_name = line.strip()
                        comp_name = comp_name.replace('sAMAccountName: ', '')
                        comp_name = comp_name.replace('$', '')
                        try:
                            comp_ip = socket.gethostbyname(comp_name)
                            if comp_ip:
                                print(f'{comp_name} - {comp_ip}')
                            else:
                                continue
                        except socket.gaierror:
                            pass
                f.close()
        else:
            pass

    def server_search(self):
        # Query LDAP for computer accounts
        self.conn.search(f'{self.dom_1}', '(&(objectClass=computer)(!(objectclass=msDS-ManagedServiceAccount)))',
                         attributes=['name', 'operatingsystem'])
        entries_val = self.conn.entries
        print('\n' + '-'*37 + 'Servers' + '-'*36 + '\n')
        entries_val = str(entries_val)
        for comp_account in self.conn.entries:
            comp_account1 = str(comp_account).lower()
            if "server" in comp_account1:
                print(f"{comp_account.name} - {comp_account.operatingsystem}")
        if os.path.exists(f"{self.dir_name}\\{self.domain}.servers.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.servers.txt")
        with open(f"{self.dir_name}\\{self.domain}.servers.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def deprecated_os(self):
        self.conn.search(f'{self.dom_1}', '(operatingSystem=*)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*26 + 'Deprecated Operating Systems' + '-'*26 + '\n')
        out_val = ''
        for deprecated in self.conn.entries:
            deprecated1 = str(deprecated)
            deprecated2 = deprecated1.lower()
            out_val = f"{deprecated.name} - {deprecated.operatingsystem}"
            if "windows 7" in deprecated2:
                print(out_val)
            if "2003" in deprecated2:
                print(out_val)
            if "windows 2008" in deprecated2:
                print(out_val)
            if "windows 8" in deprecated2:
                print(out_val)
            if "windows xp" in deprecated2:
                print(out_val)
            if "windows vista" in deprecated2:
                print(out_val)
            if os.path.exists(f"{self.dir_name}\\{self.domain}.deprecated_os.txt"):
                os.remove(f"{self.dir_name}\\{self.domain}.deprecated_os.txt")
            with open(f"{self.dir_name}\\{self.domain}.deprecated_os.txt", 'a') as f:
                f.write(out_val)
                f.close()

    def ad_search(self):
        # Query LDAP for domain controllers
        self.conn.search(f'{self.dom_1}', '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*31 + 'Domain Controllers' + '-'*31 + '\n')
        entries_val = str(entries_val)
        for dc_accounts in self.conn.entries:
            try:
                print(dc_accounts.dNSHostName)
            except ldap3.core.exceptions.LDAPCursorAttributeError:
                print(dc_accounts.name)

        if os.path.exists(f"{self.dir_name}\\{self.domain}.domaincontrollers.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.domaincontrollers.txt")
        with open(f"{self.dir_name}\\{self.domain}.domaincontrollers.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def trusted_domains(self):
        self.conn.search(f'{self.dom_1}', '(objectclass=trusteddomain)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*33 + 'Trusted Domains' + '-'*32 + '\n')
        entries_val = str(entries_val)
        for trust_vals in self.conn.entries:
            if trust_vals.trustDirection == 0:
                trust_id = "Disabled"
            if trust_vals.trustDirection == 1:
                trust_id = "<- Inbound"
            if trust_vals.trustDirection == 2:
                trust_id = "-> Outbound"
            if trust_vals.trustDirection == 3:
                trust_id = "<-> Bi-Directional"

                print(f"{trust_id} trust with {trust_vals.trustPartner}")
        if os.path.exists(f"{self.dir_name}\\{self.domain}.domaintrusts.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.domaintrusts.txt")
        with open(f"{self.dir_name}\\{self.domain}.domaintrusts.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def mssql_search(self):
        # Query LDAP for MSSQL Servers
        self.conn.search(f'{self.dom_1}', '(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*34 + 'MSSQL Servers' + '-'*33 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.mssqlservers.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.mssqlservers.txt")
        with open(f"{self.dir_name}\\{self.domain}.mssqlservers.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        with open(f"{self.dir_name}\\{self.domain}.mssqlservers.txt", 'r+') as f:
            comp_val = 0
            for line in f:
                if line.startswith('    dNSHostName: '):
                    comp_name = line.strip()
                    comp_name = comp_name.replace('dNSHostName: ', '')
                    comp_name = comp_name.replace('$', '')
                    print(comp_name)
                    comp_val += 1
                    if comp_val >= 25:
                        print_info(f'\n[info] Truncating results at 25. Check {self.domain}.computers.txt for full details.')
                        break
            f.close()

    def exchange_search(self):
        # Query LDAP for Exchange Servers
        self.conn.search(f'{self.dom_1}', '(&(objectCategory=Computer)(servicePrincipalName=exchangeMDB*))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*32 + 'Exchange Servers' + '-'*32 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.exchangeservers.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.exchangeservers.txt")
        with open(f"{self.dir_name}\\{self.domain}.exchangeservers.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        with open(f"{self.dir_name}\\{self.domain}.exchangeservers.txt", 'r+') as f:
            comp_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    comp_name = line.strip()
                    comp_name = comp_name.replace('sAMAccountName: ', '')
                    comp_name = comp_name.replace('$', '')
                    print(comp_name)
                    comp_val += 1
                    if comp_val >= 25:
                        print_info(f'\n[info] Truncating results at 25. Check {self.domain}.computers.txt for full details.')
                        break
            f.close()

    def gpo_search(self):
        # Query LDAP for Group Policy Objects (GPO)
        self.conn.search(f'{self.dom_1}', '(objectclass=groupPolicyContainer)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*30 + 'Group Policy Objects' + '-'*30 + '\n')
        entries_val = str(entries_val)
        for gpo_val in self.conn.entries:
            print(
                f"GPO name: {gpo_val.displayName}\nGPO File Path: {gpo_val.gPCFileSysPath}\n")
        if os.path.exists(f"{self.dir_name}\\{self.domain}.GPO.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.GPO.txt")
        with open(f"{self.dir_name}\\{self.domain}.GPO.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def admin_count_search(self):
        # Query LDAP for users with adminCount=1
        self.conn.search(f'{self.dom_1}', '(&(!(memberof=Builtin))(adminCount=1)(objectclass=person)(objectCategory=Person))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*30 + 'Protected Admin Users' + '-'*29 +
              '\nThese are user accounts with adminCount=1 set\n')
        entries_val = str(entries_val)
        for admin_count_val in self.conn.entries:
            print(admin_count_val.name)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.admincount.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.admincount.txt")
        with open(f"{self.dir_name}\\{self.domain}.admincount.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        print_success(f'\n[success] Information dump completed. Text files containing raw data have been placed in this directory for your review.\n')

    def find_fields(self):
        print_info('\n[info] Checking user descriptions for interesting information.')
        self.conn.search(f"{self.dom_1}", '(&(objectClass=person)(objectCategory=Person))', attributes=[
                         'sAMAccountname', 'description'])
        for entry in self.conn.entries:
            if entry.description == 'Built-in account for administering the computer/domain':
                pass
            if entry.description == 'Built-in account for guest access to the computer/domain':
                pass
            val1 = str(entry.description)
            val2 = str(entry.sAMAccountname)
            # pass_val = 'pass'
            val3 = val1.lower()
            if "pass" in val3 or "pwd" in val3 or "cred" in val3:
                print_success(f'User: {val2} - Description: {val1}')

        self.t2 = datetime.now()
        total = self.t2 - self.t1
        total = str(total)
        print_info(f"\nLDAP enumeration completed in {total}.")
        self.conn.unbind()
        quit()

    def run(self):
        init()
        self.banner()
        self.arg_handler()
        try:
            if self.subnet:
                self.portscan()
            if self.args.anon:
                self.anonymous_bind()
            elif self.args.ntlm:
                self.password = f"aad3b435b51404eeaad3b435b51404ee:{self.args.ntlm}"
                print_info(f"Using NTLM hash: {self.password}")
                self.ntlm_bind()
            elif self.args.password:
                self.authenticated_bind()
        except ValueError as ve:
            print_error(str(ve))
            self.run()
        except KeyboardInterrupt:
            print_info('\n[info] Interrupted by user. Exiting...')


if __name__ == "__main__":
    ldap_search = LDAPSearch()
    ldap_search.run()
