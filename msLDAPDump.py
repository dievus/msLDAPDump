import ipaddress
import socket
from ldap3 import Server, Connection, ALL, NTLM
import ldap3
from colorama import Fore, Style, init
import sys
from datetime import datetime
import os
import os.path
import argparse
import textwrap


class LDAPSearch:
    def __init__(self):
        self.args = None
        self.username = None
        self.password = None
        self.hostname = None
        self.server = None
        self.dom_con = None
        self.name_context = None
        self.dom_1 = None
        self.dc_val = None
        self.long_dc = None
        self.conn = None
        self.domain = None
        self.info = Fore.YELLOW + Style.BRIGHT
        self.fail = Fore.RED + Style.BRIGHT
        self.success = Fore.GREEN + Style.BRIGHT
        self.close = Style.RESET_ALL
        self.t1 = None
        self.t2 = None

    def banner(self):
        print(self.info + "")
        print('                   __    ____  ___    ____  ____')
        print('   ____ ___  _____/ /   / __ \/   |  / __ \/ __ \__  ______ ___  ____')
        print('  / __ `__ \/ ___/ /   / / / / /| | / /_/ / / / / / / / __ `__ \/ __ \ ')
        print(' / / / / / (__  ) /___/ /_/ / ___ |/ ____/ /_/ / /_/ / / / / / / /_/ /')
        print('/_/ /_/ /_/____/_____/_____/_/  |_/_/   /_____/\__,_/_/ /_/ /_/ .___/')
        print('                   Active Directory LDAP Enumerator          /_/ v1.0')
        print("                     Another Project by TheMayor \n" + self.close)

    def arg_handler(self):
        opt_parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, epilog=textwrap.dedent(
            '''Anonymous Bind: python3 msldapdump.py -a --dc 192.168.1.79\n\nAuthenticated Bind: python3 msldapdump.py --dc 192.168.1.79 --user testuser --password Password123!\n\nNTLM Authenticated Bind: python3 msldapdump.py --dc 192.168.1.79 --user testuser --ntlm <hash>\n'''))
        opt_parser_target = opt_parser.add_argument_group('Target')
        opt_parser_target.add_argument(
            '-d', '--dc', help='Sets the domain controller IP. (Required)', required=True)
        opt_parser_anon = opt_parser.add_argument_group('Anonymous Bind')
        opt_parser_anon.add_argument(
            '-a', '--anon', help='Specify anonymous bind checks only.', action='store_true'
        )
        opt_parser_auth = opt_parser.add_argument_group('Authenticated Bind')
        opt_parser_auth.add_argument(
            '-u', '--user', help='Sets the username to authenticate with.')
        opt_parser_auth.add_argument(
            '-p', '--password', help='Sets the password to authenticate with.')
        opt_parser_auth.add_argument(
            '-n', '--ntlm', help='The NTLM hash to use in place of a password.')
        self.args = opt_parser.parse_args()
        if len(sys.argv) == 1:
            opt_parser.print_help()
            opt_parser.exit()
        self.hostname = self.args.dc
        self.username = self.args.user
        self.password = self.args.password

    def anonymous_bind(self):
        try:
            self.t1 = datetime.now()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(5)
            try:
                s.connect(self.hostname, 636)
                self.server = Server(str(self.hostname),
                                     port=636, use_ssl=True, get_info=ALL)
            except:
                self.server = Server(str(self.hostname), get_info=ALL)
            self.conn = Connection(self.server, auto_bind=True)
            with open(f"{self.hostname}.ldapdump.txt", 'w') as f:
                f.write(str(self.server.info))
            print(
                self.info + "[info] Let's try to identify a domain naming convention for the domain.\n" + self.close)
            with open(f"{self.hostname}.ldapdump.txt", 'r') as f:
                for line in f:
                    if line.startswith("    DC="):
                        self.name_context = line.strip()
                        self.long_dc = self.name_context
                        self.dc_val = (self.name_context.count('DC='))
                        self.name_context = self.name_context.replace(
                            "DC=", "")
                        self.name_context = self.name_context.replace(",", ".")
                        if "ForestDnsZones" in self.name_context:
                            continue
                        else:
                            break
            self.domain = self.name_context
            domain_contents = self.domain.split(".")
            print(
                self.success + f"[success] Possible domain name found - {self.name_context}\n" + self.close)
            self.dom_1 = f"{self.long_dc}"
            print(
                self.info + f'[info] All set for now. Come back with credentials to dump additional domain information. Full raw output saved as {self.hostname}.ldapdump.txt\n' + self.close)
            self.t2 = datetime.now()
            total = self.t2 - self.t1
            total = str(total)
            print(self.info +
                  f"LDAP enumeration completed in {total}.\n" + self.close)
        except (ipaddress.AddressValueError, socket.herror):
            print(
                self.info + "[error] Invalid IP Address or unable to contact host. Please try again." + self.close)
            quit()
        except socket.timeout:
            print(
                self.info + "[error] Timeout while trying to contact the host. Please try again." + self.close)
            quit()
        except Exception as e:
            print(self.info + f"[error] - {e}" + self.close)
            quit()

    def authenticated_bind(self):
        try:
            self.t1 = datetime.now()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(5)
            try:
                s.connect(self.hostname, 636)
                self.server = Server(str(self.hostname),
                                     port=636, use_ssl=True, get_info=ALL)
            except:
                self.server = Server(str(self.hostname), get_info=ALL)
            self.conn = Connection(self.server, auto_bind=True)
            with open(f"{self.hostname}.ldapdump.txt", 'w') as f:
                f.write(str(self.server.info))
            print(
                self.info + "[info] Let's try to identify a domain naming convention for the domain.\n" + self.close)
            with open(f"{self.hostname}.ldapdump.txt", 'r') as f:
                for line in f:
                    if line.startswith("    DC="):
                        self.name_context = line.strip()
                        self.long_dc = self.name_context
                        self.dc_val = (self.name_context.count('DC='))
                        self.name_context = self.name_context.replace(
                            "DC=", "")
                        self.name_context = self.name_context.replace(",", ".")
                        if "ForestDnsZones" in self.name_context:
                            continue
                        else:
                            break
            self.domain = self.name_context
            domain_contents = self.domain.split(".")
            print(
                self.success + f"[success] Possible domain name found - {self.name_context}\n" + self.close)
            self.dom_1 = f"{self.long_dc}"
            # server = Server(str(self.hostname), port=636, use_ssl=True, get_info=ALL)
            try:
                self.conn = Connection(
                    self.server, user=f"{domain_contents[self.dc_val - 2]}\\{self.username}", password=self.password, auto_bind=True)
                self.conn.bind()
            except ldap3.core.exceptions.LDAPBindError:
                print(self.info + "Invalid credentials. Please try again." + self.close)
                quit()
            print(self.success +
                  f"[success] Connected to {self.hostname}.\n" + self.close)
            self.laps(), self.search_users(), self.machine_quota(), self.search_groups(), self.admin_accounts(), self.kerberoast_accounts(), self.aspreproast_accounts(), self.unconstrained_search(), self.constrainted_search(
            ), self.computer_search(), self.ad_search(), self.trusted_domains(), self.mssql_search(), self.exchange_search(), self.gpo_search(), self.admin_count_search(), self.find_fields()

        except (ipaddress.AddressValueError, socket.herror):
            print(
                self.info + "[error] Invalid IP Address or unable to contact host. Please try again." + self.close)
            quit()
        except socket.timeout:
            print(
                self.info + "[error] Timeout while trying to contact the host. Please try again." + self.close)
            quit()
        except Exception as e:
            print(self.info + f"[error] - {e}" + self.close)
            quit()

    def ntlm_bind(self):
        try:
            self.t1 = datetime.now()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(5)
            try:
                s.connect(self.hostname, 636)
                self.server = Server(str(self.hostname),
                                     port=636, use_ssl=True, get_info=ALL)
            except:
                self.server = Server(str(self.hostname), get_info=ALL)
            self.conn = Connection(self.server, auto_bind=True)
            with open(f"{self.hostname}.ldapdump.txt", 'w') as f:
                f.write(str(self.server.info))
            print(
                self.info + "[info] Let's try to identify a domain naming convention for the domain.\n" + self.close)
            with open(f"{self.hostname}.ldapdump.txt", 'r') as f:
                for line in f:
                    if line.startswith("    DC="):
                        self.name_context = line.strip()
                        self.long_dc = self.name_context
                        self.dc_val = (self.name_context.count('DC='))
                        self.name_context = self.name_context.replace(
                            "DC=", "")
                        self.name_context = self.name_context.replace(",", ".")
                        if "ForestDnsZones" in self.name_context:
                            continue
                        else:
                            break
            self.domain = self.name_context
            domain_contents = self.domain.split(".")
            print(
                self.success + f"[success] Possible domain name found - {self.name_context}\n" + self.close)
            self.dom_1 = f"{self.long_dc}"
            try:
                self.conn = Connection(
                    self.server, user=f"{self.domain}\\{self.username}", password=self.password, auto_bind=True, authentication=NTLM)
                self.conn.bind()
            except ldap3.core.exceptions.LDAPBindError:
                print(self.info + "Invalid credentials. Please try again." + self.close)
                quit()

            print(self.success +
                  f"[success] Connected to {self.hostname}.\n" + self.close)
            self.laps(), self.search_users(), self.machine_quota(), self.search_groups(), self.admin_accounts(), self.kerberoast_accounts(), self.aspreproast_accounts(), self.unconstrained_search(), self.constrainted_search(
            ), self.computer_search(), self.ad_search(), self.trusted_domains(), self.mssql_search(), self.exchange_search(), self.gpo_search(), self.admin_count_search(), self.find_fields()
        except (ipaddress.AddressValueError, socket.herror):
            print(
                self.info + "[error] Invalid IP Address or unable to contact host. Please try again." + self.close)
            quit()
        except socket.timeout:
            print(
                self.info + "[error] Timeout while trying to contact the host. Please try again." + self.close)
            quit()
        except Exception as e:
            print(self.info + f"[error] - {e}" + self.close)
            quit()

    def laps(self):
        # Check for LAPS passwords accessible to the current user

        print('\n' + '-'*33 + 'LAPS Passwords' + '-'*33 +
              '\n This relies on the current user having permissions to read LAPS passwords\n')
        try:
            self.conn.search(
                f'{self.dom_1}', '(ms-MCS-AdmPwd=*)', attributes=['ms-Mcs-AdmPwd'])
            entries_val = self.conn.entries
            entries_val = str(entries_val)
            print(entries_val)
        except Exception:
            pass

    def search_users(self):
        # Search domain users

        self.conn.search(
            f'{self.dom_1}', '(&(objectclass=person)(objectCategory=Person))', attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*38 + 'Users' + '-'*37 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.domain}.users.txt"):
            os.remove(f"{self.domain}.users.txt")
        with open(f"{self.domain}.users.txt", 'w') as f:
            f.write(entries_val)
            f.close
        for users in self.conn.entries:
            print(users.sAMAccountName)

    def machine_quota(self):
        # Query ms-DS-MachineAccountQuota
        self.conn.search(f'{self.dom_1}', '(objectclass=*)',
                         attributes=['ms-DS-MachineAccountQuota'])
        entries_val = self.conn.entries[0]
        print('\n' + '-'*30 + 'Machine Account Quota' + '-'*29 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.domain}.machine_quota.txt"):
            os.remove(f"{self.domain}.machine_quota.txt")
        with open(f"{self.domain}.machine_quota.txt", 'w') as f:
            f.write(entries_val)
            f.close
        with open(f"{self.domain}.machine_quota.txt", 'r+') as f:
            machine_val = 0
            for line in f:
                if line.startswith('    ms-DS-MachineAccountQuota: '):
                    machine_quota = line.strip()
                    print(machine_quota)
                    machine_val += 1
                    if machine_val >= 25:
                        print(
                            self.info + f'\n[info] Truncating results at 25. Check {self.domain}.machine_quota.txt for full details.' + self.close)
                        break
            f.close()

    def search_groups(self):
        # Query LDAP for groups
        self.conn.search(f'{self.dom_1}', '(objectclass=group)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*37 + 'Groups' + '-'*37 + '\n')
        entries_val = str(entries_val)
        for group in self.conn.entries:
            print(group.sAMAccountName)
        if os.path.exists(f"{self.domain}.groups.txt"):
            os.remove(f"{self.domain}.groups.txt")
        with open(f"{self.domain}.groups.txt", 'w') as f:
            f.write(entries_val)
            f.close

    def admin_accounts(self):
        admin_users = []
        self.conn.search(f'{self.dom_1}', '(&(objectclass=group)(CN=*admin*))',
                         attributes=['member'])
        entries_val = str(self.conn.entries)
        self.conn.search(f'{self.dom_1}', '(&(objectclass=group)(CN=*operator*))',
                         attributes=['member'])
        print('\n' + '-'*30 + 'Admin Level Users' + '-'*30 + '\n')
        entries_val1 = str(self.conn.entries)
        # print(entries_val)
        if os.path.exists(f"{self.domain}.adminusers.txt"):
            os.remove(f"{self.domain}.adminusers.txt")
        with open(f"{self.domain}.adminusers.txt", 'w') as f:
            f.write(entries_val)
            f.write(entries_val1)
            f.close()
        with open(f"{self.domain}.adminusers.txt", 'r+') as f:
            admin_val = 0
            for line in f:
                if line.startswith('    member: '):
                    admin_name = line.strip()
                    admin_name = admin_name.replace('member: ', '')
                    if admin_name not in admin_users:
                        print(admin_name)
                        admin_users.append(admin_name)
                        admin_val += 1
                    else:
                        pass
                    if admin_val >= 25:
                        print(
                            self.info + f'\n[info] Truncating results at 25. Check {self.domain}.adminusers.txt for full details.' + self.close)
                        break
            f.close()

    def kerberoast_accounts(self):
        # Query LDAP for Kerberoastable users
        self.conn.search(f'{self.dom_1}', '(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
                         attributes=[ldap3.ALL_ATTRIBUTES])
        entries_val = self.conn.entries
        print('\n' + '-'*30 + 'Kerberoastable Users' + '-'*30 + '\n')
        entries_val = str(entries_val)
        for kerb_users in self.conn.entries:
            print(kerb_users.sAMAccountName)
        if os.path.exists(f"{self.domain}.kerberoast.txt"):
            os.remove(f"{self.domain}.kerberoast.txt")
        with open(f"{self.domain}.kerberoast.txt", 'w') as f:
            f.write(entries_val)
            f.close()

    def aspreproast_accounts(self):
        # Query LDAP for ASREPRoastable Users
        self.conn.search(f'{self.dom_1}', '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', attributes=[
            'sAMAccountName'])
        entries_val = self.conn.entries
        print('\n' + '-'*30 + 'ASREPRoastable Users' + '-'*30 + '\n')
        entries_val = str(entries_val)
        for asrep_users in self.conn.entries:
            print(asrep_users.sAMAccountName)
        if os.path.exists(f"{self.domain}.asreproast.txt"):
            os.remove(f"{self.domain}.asreproast.txt")
        with open(f"{self.domain}.asreproast.txt", 'w') as f:
            f.write(entries_val)
            f.close()

    def unconstrained_search(self):
        # Query LDAP for Unconstrained Delegation Rights
        self.conn.search(f'{self.dom_1}', "(&(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*28 + 'Unconstrained Delegations' + '-'*27 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.domain}.unconstrained.txt"):
            os.remove(f"{self.domain}.unconstrained.txt")
        with open(f"{self.domain}.unconstrained.txt", 'w') as f:
            f.write(entries_val)
            f.close()
        with open(f"{self.domain}.unconstrained.txt", 'r+') as f:
            uncon_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    uncon_name = line.strip()
                    uncon_name = uncon_name.replace('sAMAccountName: ', '')
                    print(f'{uncon_name}')
                    uncon_val += 1
                    if uncon_val >= 25:
                        print(
                            self.info + f'\n[info] Truncating results at 25. Check {self.domain}.unconstrained.txt for full details.' + self.close)
                        break
            f.close()

    def constrainted_search(self):
        # Query LDAP for Constrained Delegation Rights
        self.conn.search(f'{self.dom_1}', "(msDS-AllowedToDelegateTo=*)",
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*29 + 'Constrained Delegations' + '-'*28 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.domain}.constrained.txt"):
            os.remove(f"{self.domain}.constrained.txt")
        with open(f"{self.domain}.constrained.txt", 'w') as f:
            f.write(entries_val)
            f.close()
        with open(f"{self.domain}.constrained.txt", 'r+') as f:
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
                        print(
                            self.info + f'\n[info] Truncating results at 25. Check {self.domain}.constrained.txt for full details.' + self.close)
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
            print(comp_account.sAMAccountName)
        if os.path.exists(f"{self.domain}.computers.txt"):
            os.remove(f"{self.domain}.computers.txt")
        with open(f"{self.domain}.computers.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        if sys.platform.startswith('win32'):
            # Runs a check to see if the current system is Windows. In place until the Linux DNS resolution on multiple adapters issue is resolved.
            print(
                self.info + "\n[info] Let's try to resolve hostnames to IP addresses. This may take some time depending on the number of computers...\n" + self.close)
            with open(f"{self.domain}.computers.txt", 'r+') as f:
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

    def ad_search(self):
        # Query LDAP for domain controllers
        self.conn.search(f'{self.dom_1}', '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*31 + 'Domain Controllers' + '-'*31 + '\n')
        entries_val = str(entries_val)
        for dc_accounts in self.conn.entries:
            print(dc_accounts.dNSHostName)
        if os.path.exists(f"{self.domain}.domaincontrollers.txt"):
            os.remove(f"{self.domain}.domaincontrollers.txt")
        with open(f"{self.domain}.domaincontrollers.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def trusted_domains(self):
        self.conn.search(f'{self.dom_1}', '(trustPartner=*)',
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
        if os.path.exists(f"{self.domain}.domaintrusts.txt"):
            os.remove(f"{self.domain}.domaintrusts.txt")
        with open(f"{self.domain}.domaintrusts.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def mssql_search(self):
        # Query LDAP for MSSQL Servers
        self.conn.search(f'{self.dom_1}', '(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*34 + 'MSSQL Servers' + '-'*33 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.domain}.mssqlservers.txt"):
            os.remove(f"{self.domain}.mssqlservers.txt")
        with open(f"{self.domain}.mssqlservers.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        with open(f"{self.domain}.mssqlservers.txt", 'r+') as f:
            comp_val = 0
            for line in f:
                if line.startswith('    dNSHostName: '):
                    comp_name = line.strip()
                    comp_name = comp_name.replace('dNSHostName: ', '')
                    comp_name = comp_name.replace('$', '')
                    print(comp_name)
                    comp_val += 1
                    if comp_val >= 25:
                        print(
                            self.info + f'\n[info] Truncating results at 25. Check {self.domain}.computers.txt for full details.' + self.close)
                        break
            f.close()

    def exchange_search(self):
        # Query LDAP for Exchange Servers
        self.conn.search(f'{self.dom_1}', '(&(objectCategory=Computer)(servicePrincipalName=exchangeMDB*))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*32 + 'Exchange Servers' + '-'*32 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.domain}.exchangeservers.txt"):
            os.remove(f"{self.domain}.exchangeservers.txt")
        with open(f"{self.domain}.exchangeservers.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        with open(f"{self.domain}.exchangeservers.txt", 'r+') as f:
            comp_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    comp_name = line.strip()
                    comp_name = comp_name.replace('sAMAccountName: ', '')
                    comp_name = comp_name.replace('$', '')
                    print(comp_name)
                    comp_val += 1
                    if comp_val >= 25:
                        print(
                            self.info + f'\n[info] Truncating results at 25. Check {self.domain}.computers.txt for full details.' + self.close)
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
            print(f"GPO name: {gpo_val.displayName}\nGPO File Path: {gpo_val.gPCFileSysPath}\n")
        if os.path.exists(f"{self.domain}.GPO.txt"):
            os.remove(f"{self.domain}.GPO.txt")
        with open(f"{self.domain}.GPO.txt", 'a') as f:
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
        if os.path.exists(f"{self.domain}.admincount.txt"):
            os.remove(f"{self.domain}.admincount.txt")
        with open(f"{self.domain}.admincount.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        print(
            self.success + f'\n[success] Information dump completed. Text files containing raw data have been placed in this directory for your review.\n' + self.close)

    def find_fields(self):
        print(
            self.info + '\n[info] Checking user descriptions for interesting information.\n' + self.close)
        self.conn.search(f"{self.dom_1}", '(&(objectClass=person)(objectCategory=Person))', attributes=['sAMAccountname', 'description'])
        for entry in self.conn.entries:
            if entry.description == 'Built-in account for administering the computer/domain':
                pass
            if entry.description == 'Built-in account for guest access to the computer/domain':
                pass
            val1 = str(entry.description)
            val2 = str(entry.sAMAccountname)
            pass_val = 'pass'
            val3 = val1.lower()
            if pass_val in val3:
                print(self.success + f'User: {val2} - Description: {val1}' + self.close)   

        self.t2 = datetime.now()
        total = self.t2 - self.t1
        total = str(total)
        print(self.info +
                f"\nLDAP enumeration completed in {total}.\n" + self.close)
        quit()

    def run(self):
        init()
        try:
            ldap_search.banner()
            self.arg_handler()
            if self.args.anon:
                self.anonymous_bind()
            elif self.args.ntlm:
                self.password = f"aad3b435b51404eeaad3b435b51404ee:{self.args.ntlm}"
                self.ntlm_bind()
            elif self.args.password:
                self.password = self.args.password
                self.authenticated_bind()
            self.conn.unbind()
        except ValueError as ve:
            print(ve)
            self.run()
        except KeyboardInterrupt:
            print(
                self.info + '\n[info] You either fat fingered this or something else. Either way, quitting...\n' + self.close)


ldap_search = LDAPSearch()
ldap_search.run()
