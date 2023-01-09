import ldap3
from ldap3 import Server, Connection, ALL
import time
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
    print('                   Active Directory LDAP Enumerator          /_/       v1.0')
    print("                Another unnecessary gizmo by The Mayor           \n" + Style.RESET_ALL)


def ldap_search():
    global domain
    try:
        username = input('Username (Y/N): ')
        if username == 'y' or username == 'Y':
            username1 = input('Enter the username here (no domain): ')
            password = input('Password (Y/N): ')
            if password == 'y' or password == 'Y':
                password1 = getpass('Enter the password here: ')
            elif password == 'n' or password == 'N':
                print(
                    '\n[info] No credentials, no problem. Binding to LDAP anonymously. Anonymous bind only allows dumping of basic information.')
                dom_con = input('\nDomain Controller IP: ')
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
                        fail + '[error] Unable to contact target host. Quitting...\n' + close)
                    quit()
                server = Server(dom_con, get_info=ALL)
                conn = Connection(server, auto_bind=True)
                print('-'*80)
                print(
                    info + '\n[info] Printing out a bunch of information on the target domain. Find Naming Contexts and enter the domain name from it.\n' + close)
                print(
                    info + '[info] This will be needed later when authenticating, and is good information to have for enumeration.\n' + close)
                print('-'*80)
                time.sleep(2)
                print(server.info)
                info_server = str(server.info)
                with open(f"{hostname}.ldapdump.txt", 'a') as f:
                    f.write(info_server)
                    f.close()
                conn.unbind()
                print(
                    info + f'[info] All set for now. Come back with credentials to dump additional domain information. Information saved as {hostname}.ldapdump.txt\n' + close)
                quit()
        elif username == 'n' or username == 'N':
            print(
                info + '\n[info] No credentials, no problem. Binding to LDAP anonymously. Anonymous bind only allows dumping of basic information.' + close)
            dom_con = input('\nDomain Controller IP: ')
            server = Server(dom_con, get_info=ALL)
            conn = Connection(server, auto_bind=True)
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
                    fail + '[error] Unable to contact target host. Quitting...\n' + close)
                quit()
            print('-'*80)
            print(
                info + '\n[info] Printing out a bunch of information on the target domain. Find Naming Contexts and enter the domain name from it.\n')
            print('[info] This will be needed later when authenticating, and is good information to have for enumeration.\n' + close)
            print('-'*80)
            time.sleep(2)
            print(server.info)
            info_server = str(server.info)
            with open(f"{hostname}.ldapdump.txt", 'a') as f:
                f.write(info_server)
                f.close()
            conn.unbind()
            print(
                info + f'[info] All set for now. Come back with credentials to dump additional domain information. Information saved as {hostname}.ldapdump.txt\n' + close)
            quit()
        else:
            print(
                fail + '\n[error] Invalid selection. Please enter valid selections and try again' + close)
            ldap_search()
        dom_con = input('\nDomain Controller IP: ')
        know_dom = input('\nDo you know the domain name? (Y/N): ')
        if know_dom == 'Y' or know_dom == 'y':
            domain = input('Domain name: ')
        elif know_dom == 'N' or know_dom == 'n':
            print(
                info + "\n[info] Let's try to find the domain name. You can locate it under Naming contexts.\n" + close)
            # print('[info] This will be needed later when authenticating, and is good information to have for enumeration.\n' + close)
            time.sleep(2)
            server = Server(dom_con, get_info=ALL)
            conn = Connection(server, auto_bind=True)
            print(server.info)
            conn.unbind()
            domain = input('Domain name: ')
        domain_contents = domain.split(".")
        domain = domain_contents[0]
        dom_1 = f"DC={domain_contents[0]},DC={domain_contents[1]}"
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
                fail + '[error] Unable to contact target host. Quitting...\n' + close)
            quit()
        if username == 'n' or username == 'N' or password == 'n' or password == 'N':
            print(
                info + '[info] End of the line. Once you have credentials you can authenticate and dump additional information.\n' + close)
            quit()
        print(info + "[info] Let's dump some LDAP info...\n" + close)
        server = Server(hostname, get_info=ALL)
        conn = Connection(
            server, user=f"{domain}\\{username1}", password=f"{password1}", auto_bind=True)
        conn.bind()
        whoami = conn.extend.standard.who_am_i()
        print('-'*34 + 'Current User' + '-'*34 + '\n' + whoami)
        time.sleep(2)
        with open(f"{domain}.ldapdump.txt", 'a') as f:
            f.write(whoami)
            f.close()
        conn.search(f'{dom_1}', '(objectclass=person)',
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*38 + 'Users' + '-'*37 + '\n')
        time.sleep(2)
        print(entries_val)
        entries_val = str(entries_val)
        with open(f"{domain}.ldapdump.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        conn.search(f'{dom_1}', '(objectclass=computer)',
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*36 + 'Computers' + '-'*35 + '\n')
        time.sleep(2)
        print(entries_val)
        entries_val = str(entries_val)
        with open(f"{domain}.ldapdump.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        conn.search(f'{dom_1}', '(objectclass=groupPolicyContainer)',
                    attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = conn.entries
        print('\n' + '-'*30 + 'Group Policy Objects' + '-'*30 + '\n')
        time.sleep(2)
        print(entries_val)
        entries_val = str(entries_val)
        with open(f"{domain}.ldapdump.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        print(entries_val)
        conn.unbind()
        time.sleep(2)
        print(
            success + f'\n[success] Information dump completed. A text file named {domain}.ldapdump.txt has been placed in this directory for your review.\n' + close)
        time.sleep(2)
        find_fields()
    except KeyboardInterrupt:
        print(
            info + '\n\n[info] You either fat fingered this or something else. Either way, quitting...\n' + close)
    except Exception as e:
        print(fail + f'[error] - {e}. Quitting...\n')


def find_fields():
    descript_info = []
    idx = 0
    print(
        info + '[info] Checking the output for information in description fields.\n' + close)
    with open(f'{domain}.ldapdump.txt', 'r') as refile:
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
            # descriptions = re.search("Description:", refile)
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
