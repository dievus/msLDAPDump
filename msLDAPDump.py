import ldap3
from ldap3 import Server, Connection, ALL
import time
import ipaddress
from getpass import getpass
import socket
from colorama import Fore, Style, init


def definitions():
    global info, close, success, fail
    info, fail, close, success = Fore.YELLOW + Style.BRIGHT, Fore.RED + \
        Style.BRIGHT, Style.RESET_ALL, Fore.GREEN + Style.BRIGHT


def banner():
    print(Fore.YELLOW + Style.BRIGHT + "")
    print('                   __    ____  ___    ____  ____')
    print('   ____ ___  _____/ /   / __ \/   |  / __ \/ __ \__  ______ ___  ____')
    print('  / __ `__ \/ ___/ /   / / / / /| | / /_/ / / / / / / / __ `__ \/ __ \ ')
    print(' / / / / / (__  ) /___/ /_/ / ___ |/ ____/ /_/ / /_/ / / / / / / /_/ /')
    print('/_/ /_/ /_/____/_____/_____/_/  |_/_/   /_____/\__,_/_/ /_/ /_/ .___/')
    print('                   Active Directory LDAP Enumerator          /_/ v1.0')
    print("                     Another Project by TheMayor \n" + Style.RESET_ALL)


def ldap_search():
    global domain
    global hostname
    try:
        username = input('Username (Y/N): ')
        if username == 'y' or username == 'Y':
            username1 = input('Enter the username here (no domain): ')
            password = input('Password (Y/N): ')
            if password == 'y' or password == 'Y':
                password1 = getpass('Enter the password here: ')
            elif password == 'n' or password == 'N':
                print(
                    info + '\n[info] No credentials, no problem. Binding to LDAP anonymously. Anonymous bind only allows dumping of basic information.' + close)
                try:
                    dom_con = ipaddress.ip_address(
                        input('\nDomain Controller IP: '))
                    dom_con = str(dom_con)
                    print(
                        info + '\n[info] Trying to identify the domain controller hostname...\n' + close)
                except KeyboardInterrupt:
                    print(
                        info + '\n\n[info] You either fat fingered this or something else. Either way, goodbye...' + close)
                    quit()
                except ValueError:
                    print(info + "Invalid IP Address. Please try again." + close)
                    ldap_search()
                try:
                    sock_host = socket.gethostbyaddr(dom_con)
                    hostname = sock_host[0]
                    if hostname is not None:
                        print(
                            success + '[success] Target hostname is ' + hostname + '\n' + close)
                    else:
                        print(
                            info + '[info] Could not identify target hostname. Continuing...\n' + close)
                        hostname = dom_con
                except Exception:
                    print(
                        fail + '\n[error] Unable to contact target host. Quitting...\n' + close)
                    quit()
                server = Server(dom_con, get_info=ALL)
                conn = Connection(server, auto_bind=True)
                print(
                    info + "[info] Let's try to identify a domain naming convention for the domain.\n" + close)
                info_server = str(server.info)
                with open(f"{hostname}.ldapdump.txt", 'a') as f:
                    f.write(info_server)
                    f.close()
                with open(f"{hostname}.ldapdump.txt", 'r') as f:
                    for line in f:
                        try:
                            if line.startswith("    DC="):
                                name_context = line.strip()
                                name_context = name_context.replace("DC=", "")
                                name_context = name_context.replace(",", ".")
                                print(
                                    success + f"[success] Possible domain name found - {name_context}\n" + close)
                                break
                        except Exception:
                            print(
                                info + '[info] Domain name not found. Quitting...\n' + close)
                            quit()
                conn.unbind()
                print(
                    info + f'[info] All set for now. Come back with credentials to dump additional domain information. Full raw output saved as {hostname}.ldapdump.txt\n' + close)
                quit()
            else:
                print(
                    fail + '\n[error] Invalid selection. Please enter valid selections and try again' + close)
                ldap_search()
        elif username == 'n' or username == 'N':
            print(
                info + '\n[info] No credentials, no problem. Binding to LDAP anonymously. Anonymous bind only allows dumping of basic information.' + close)
            try:
                dom_con = ipaddress.ip_address(
                    input('\nDomain Controller IP: '))
                dom_con = str(dom_con)
                print(
                    info + '\n[info] Trying to identify the domain controller hostname...\n' + close)
            except KeyboardInterrupt:
                print(
                    info + '\n\n[info] You either fat fingered this or something else. Either way, goodbye...' + close)
                quit()
            except ValueError:
                print(info + "Invalid IP Address. Please try again." + close)
                ldap_search()
            server = Server(dom_con, get_info=ALL)
            conn = Connection(server, auto_bind=True)
            try:
                sock_host = socket.gethostbyaddr(dom_con)
                hostname = sock_host[0]
                if hostname is not None:
                    print(
                        success + '[success] Target hostname is ' + hostname + '\n' + close)
                else:
                    print(
                        info + '[info] Could not identify target hostname. Continuing...\n' + close)

                    hostname = dom_con
            except Exception:
                print(
                    fail + '\n[error] Unable to contact target host. Quitting...\n' + close)
                quit()
            server = Server(dom_con, get_info=ALL)
            conn = Connection(server, auto_bind=True)
            print(
                info + "[info] Let's try to identify a domain naming convention for the domain.\n" + close)
            info_server = str(server.info)
            with open(f"{hostname}.ldapdump.txt", 'a') as f:
                f.write(info_server)
                f.close()
            with open(f"{hostname}.ldapdump.txt", 'r') as f:
                for line in f:
                    try:
                        if line.startswith("    DC="):
                            name_context = line.strip()
                            name_context = name_context.replace("DC=", "")
                            name_context = name_context.replace(",", ".")
                            print(
                                success + f"[success] Possible domain name found - {name_context}\n" + close)
                            break
                    except Exception:
                        print(
                            info + '[info] Domain name not found. Quitting...' + close)
                        quit()
            print(
                info + f'[info] All set for now. Come back with credentials to dump additional domain information. Full raw output saved as {hostname}.ldapdump.txt\n' + close)
            quit()
        else:
            print(
                fail + '\n[error] Invalid selection. Please enter valid selections and try again' + close)
            ldap_search()
        dom_con = ipaddress.ip_address(input('\nDomain Controller IP: '))
        dom_con = str(dom_con)
        print(
            info + '\n[info] Trying to identify the domain controller hostname...\n' + close)
        try:
            sock_host = socket.gethostbyaddr(dom_con)
            hostname = sock_host[0]
            if hostname is not None:
                print(
                    success + '[success] Target hostname is ' + hostname + '\n' + close)
            else:
                print(
                    info + '[info] Could not identify target hostname. Continuing...\n' + close)

                hostname = dom_con
        except Exception:
            print(
                fail + '\n[error] Unable to contact target host. Quitting...\n' + close)
            quit()
        print(
            info + "[info] Let's try to identify a domain naming convention for the domain.\n" + close)
        server = Server(dom_con, get_info=ALL)
        conn = Connection(server, auto_bind=True)
        info_server = str(server.info)
        with open(f"{hostname}.ldapdump.txt", 'a') as f:
            f.write(info_server)
            f.close()
        with open(f"{hostname}.ldapdump.txt", 'r') as f:
            for line in f:
                try:
                    if line.startswith("    DC="):
                        name_context = line.strip()
                        name_context = name_context.replace("DC=", "")
                        name_context = name_context.replace(",", ".")
                        print(
                            success + f"[success] Possible domain name found - {name_context}\n" + close)
                        break
                except Exception:
                    print(
                        info + '[info] Domain name not found. Quitting...' + close)
                    quit()
        domain = name_context
        domain_contents = domain.split(".")
        domain = domain_contents[0]
        dom_1 = f"DC={domain_contents[0]},DC={domain_contents[1]}"

        if username == 'n' or username == 'N' or password == 'n' or password == 'N':
            print(
                info + '[info] End of the line. Once you have credentials you can authenticate and dump additional information.\n' + close)
            quit()
        print(info + "[info] Let's dump some LDAP info...\n" + close)
        server = Server(hostname, get_info=ALL)
        conn = Connection(
            server, user=f"{domain}\\{username1}", password=f"{password1}", auto_bind=True)
        conn.bind()

        # Current User Check/Confirm
        whoami = conn.extend.standard.who_am_i()
        print('-'*34 + 'Current User' + '-'*34 + '\n' + whoami)

        # Query LDAP for users accounts
        conn.search(f'{dom_1}', '(&(objectclass=person)(objectCategory=Person))',
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*38 + 'Users' + '-'*37 + '\n')
        entries_val = str(entries_val)
        with open(f"{domain}.users.txt", 'w') as f:
            f.write(entries_val)
            f.close
        with open(f"{domain}.users.txt", 'r+') as f:
            user_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    sam_name = line.strip()
                    sam_name = sam_name.replace('sAMAccountName: ', '')
                    print(sam_name)
                    user_val += 1
                    if user_val >= 25:
                        print(
                            info + f'\n[info] Truncating results at 25. Check {domain}.users.txt for full details.' + close)
                        break
            f.close()

        # Query LDAP for groups
        conn.search(f'{dom_1}', '(objectclass=group)',
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*37 + 'Groups' + '-'*37 + '\n')
        entries_val = str(entries_val)
        with open(f"{domain}.groups.txt", 'w') as f:
            f.write(entries_val)
            f.close
        with open(f"{domain}.groups.txt", 'r+') as f:
            group_val = 0
            for line in f:
                if line.startswith('    name: '):
                    group_name = line.strip()
                    group_name = group_name.replace('name: ', '')
                    print(group_name)
                    group_val += 1
                    if group_val >= 25:
                        print(
                            info + f'\n[info] Truncating results at 25. Check {domain}.groups.txt for full details.' + close)
                        break
            f.close()

        # Query LDAP for Kerberoastable users
        conn.search(f'{dom_1}', '(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*30 + 'Kerberoastable Users' + '-'*30 + '\n')
        entries_val = str(entries_val)
        with open(f"{domain}.kerberoast.txt", 'w') as f:
            f.write(entries_val)
            f.close()
        with open(f"{domain}.kerberoast.txt", 'r+') as f:
            kerb_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    kerb_name = line.strip()
                    kerb_name = kerb_name.replace('sAMAccountName: ', '')
                    print(kerb_name)
                    kerb_val += 1
                    if kerb_val >= 25:
                        print(
                            info + f'\n[info] Truncating results at 25. Check {domain}.users.txt for full details.' + close)
                        break
            f.close()
        # Query LDAP for ASREPRoastable Users
        conn.search(f'{dom_1}', '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))', attributes=[
                    'sAMAccountName'])
        entries_val = conn.entries
        print('\n' + '-'*30 + 'ASREPRoastable Users' + '-'*30 + '\n')
        entries_val = str(entries_val)
        with open(f"{domain}.asreproast.txt", 'w') as f:
            f.write(entries_val)
            f.close()
        with open(f"{domain}.asreproast.txt", 'r+') as f:
            asrep_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    asrep_name = line.strip()
                    asrep_name = asrep_name.replace('sAMAccountName: ', '')
                    print(asrep_name)
                    asrep_val += 1
                    if asrep_val >= 25:
                        print(
                            info + f'\n[info] Truncating results at 25. Check {domain}.users.txt for full details.' + close)
                        break
            f.close()

        # Query LDAP for Unconstrained Delegation Rights
        conn.search(f'{dom_1}', "(&(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*28 + 'Unconstrained Delegations' + '-'*27 + '\n')
        entries_val = str(entries_val)
        with open(f"{domain}.unconstrained.txt", 'w') as f:
            f.write(entries_val)
            f.close()
        with open(f"{domain}.unconstrained.txt", 'r+') as f:
            uncon_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    uncon_name = line.strip()
                    uncon_name = uncon_name.replace('sAMAccountName: ', '')
                    print(f'{uncon_name}')
                    uncon_val += 1
                    if uncon_val >= 25:
                        print(
                            info + f'\n[info] Truncating results at 25. Check {domain}.constrained.txt for full details.' + close)
                        break
            f.close()

        # Query LDAP for Constrained Delegation Rights
        conn.search(f'{dom_1}', "(msDS-AllowedToDelegateTo=*)",
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*29 + 'Constrained Delegations' + '-'*28 + '\n')
        entries_val = str(entries_val)
        with open(f"{domain}.constrained.txt", 'w') as f:
            f.write(entries_val)
            f.close()
        with open(f"{domain}.constrained.txt", 'r+') as f:
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
                            info + f'\n[info] Truncating results at 25. Check {domain}.constrained.txt for full details.' + close)
                        break
            f.close()

        # Query LDAP for computer accounts
        conn.search(f'{dom_1}', '(objectClass=computer)',
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*36 + 'Computers' + '-'*35 +'\n')
        entries_val = str(entries_val)
        with open(f"{domain}.computers.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        with open(f"{domain}.computers.txt", 'r+') as f:
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
                            info + f'\n[info] Truncating results at 25. Check {domain}.computers.txt for full details.' + close)
                        break
            f.close()
        print(info + "\n[info] Let's try to resolve hostnames to IP addresses. This may take some time depending on the number of computers...\n" + close)
        with open(f"{domain}.computers.txt", 'r+') as f:
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
                        comp_val1 += 1
                        if comp_val1 >= 25:
                            print(
                                info + f'\n[info] Truncating results at 25. Check {domain}.computers.txt for full details.' + close)
                            break
                f.close()
        # Query LDAP for Group Policy Objects (GPO)
        conn.search(f'{dom_1}', '(objectclass=groupPolicyContainer)',
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*30 + 'Group Policy Objects' + '-'*30 + '\n')
        entries_val = str(entries_val)
        with open(f"{domain}.GPO.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        with open(f"{domain}.GPO.txt", 'r+') as f:
            gpo_val = 0
            for line in f:
                if line.startswith('    displayName: '):
                    gpo_name = line.strip()
                    gpo_name = gpo_name.replace('displayName: ', 'GPO Name: ')
                if line.startswith('    gPCFileSysPath: '):
                    gpcname = line.strip()
                    gpcname = gpcname.replace(
                        'gPCFileSysPath: ', 'GPO File Path: ')
                    print(f'{gpo_name}\n{gpcname}')
                    gpo_val += 1
                    if gpo_val >= 25:
                        print(
                            info + f'\n[info] Truncating results at 25 users. Check {domain}.constrained.txt for full details.' + close)
                        break
            f.close()

        # Query LDAP for users with adminCount=1
        conn.search(f'{dom_1}', '(&(!(memberof=Builtin))(adminCount=1)(objectclass=person)(objectCategory=Person))',
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*31 + 'Protected Admin Users' + '-'*30 +
              '\nThese are user accounts with adminCount=1 set\n')
        entries_val = str(entries_val)
        with open(f"{domain}.admincount.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        with open(f"{domain}.admincount.txt", 'r+') as f:
            gpo_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    admin_name = line.strip()
                    admin_name = admin_name.replace('sAMAccountName: ', '')
                    print(admin_name)
                    gpo_val += 1
                    if gpo_val >= 25:
                        print(
                            info + f'\n[info] Truncating results at 25 users. Check {domain}.admincount.txt for full details.' + close)
                        break
        f.close()
        conn.unbind()
        print(
            success + f'\n[success] Information dump completed. Text files containing raw data have been placed in this directory for your review.\n' + close)
        find_fields()
    except KeyboardInterrupt:
        print(
            info + '\n\n[info] You either fat fingered this or something else. Either way, quitting...\n' + close)
    except Exception as e:
        print(fail + f'\n[error] - {e}. Quitting...\n')
        quit()


def find_fields():
    descript_info = []
    idx = 0
    print(
        info + '\n[info] Checking the output for information in description fields.\n' + close)
    with open(f'{domain}.users.txt', 'r') as refile:
        lines = refile.readlines()
        for line in lines:
            descriptions = "description:"
            if descriptions in line:
                if "Built-in" in line or "Key Distribution Center Service Account" in line:
                    pass
                else:
                    line = line.replace('description: ', '')
                    descript_info.insert(idx, line)
                    idx += 1
    refile.close()
    if len(descript_info) == 0:
        print(info + '[info] No information identified based on static parameters. Check the output file manually. Quitting...' + close)
        quit()
    else:
        lineLen = len(descript_info)
        print(
            success + '[success] Dumped the following information from object descriptions - Check text file for full details\n' + close)
        for i in range(lineLen):
            end = descript_info[i]
            print(info + f'{end}')
        print()
        quit()


if __name__ == "__main__":
    init()
    definitions()
    banner()
    ldap_search()
