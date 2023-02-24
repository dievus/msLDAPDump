# msLDAPDump
LDAP enumeration tool implemented in Python3

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M03Q2JN)

msLDAPDump simplifies LDAP enumeration in a domain environment by wrapping the lpap3 library from Python in an easy-to-use interface. Like most of my tools, this one works best on Windows. If using Unix, the tool will not resolve hostnames that are not accessible via eth0 currently.

### Binding Anonymously

Users can bind to LDAP anonymously through the tool and dump basic information about LDAP, including domain naming context, domain controller hostnames, and more.

<p align="center">
  <img src="https://github.com/dievus/msLDAPDump/blob/main/images/anonbind.png" width="829" height="288"/>
</p>

### Credentialed Bind
<p align="center">
  <img src="https://github.com/dievus/msLDAPDump/blob/main/images/authbind.png" width="847" height="229"/>
</p>

<p align="center">
  <img src="https://github.com/dievus/msLDAPDump/blob/main/images/ntlmbind.png" width="847" height="248"/>
</p>
Users can bind to LDAP utilizing valid user account credentials or a valid NTLM hash. Using credentials will obtain the same information as the anonymously binded request, as well as checking for the following: 

* Subnet scan for systems with ports 389 and 636 open
* Basic Domain Info (Current user permissions, domain SID, password policy, machine account quota)
* Users
* Groups
* Kerberoastable Accounts
* ASREPRoastable Accounts
* Constrained Delegation
* Unconstrained Delegation
* Computer Accounts - will also attempt DNS lookups on the hostname to identify IP addresses
* Identify Domain Controllers
* Identify Servers
* Identify Deprecated Operating Systems
* Identify MSSQL Servers
* Identify Exchange Servers
* Group Policy Objects (GPO)
* Passwords in User description fields

Each check outputs the raw contents to a text file, and an abbreviated, cleaner version of the results in the terminal environment. The results in the terminal are pulled from the individual text files.

- [X] Add support for LDAPS (LDAP Secure)
- [X] NTLM Authentication
- [ ] Figure out why Unix only allows one adapter to make a call out to the LDAP server (removed resolution from Linux until resolved)
- [X] Add support for querying child domain information (currently does not respond nicely to querying child domain controllers)
- [X] Figure out how to link the name to the Description field dump at the end of the script
- [X] Implement command line options rather than inputs 
- [X] Check for deprecated operating systems in the domain
### Mandatory Disclaimer
Please keep in mind that this tool is meant for ethical hacking and penetration testing purposes only. I do not condone any behavior that would include testing targets that you do not currently have permission to test against.
