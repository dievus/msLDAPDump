# msLDAPDump
LDAP enumeration tool implemented in Python3

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M03Q2JN)

msLDAPDump simplifies LDAP enumeration in a domain environment by wrapping the lpap3 library from Python in an easy-to-use interface. Like most of my tools, this one works best on Windows. If using Unix, the tool only works when accessing an LDAP server from the primary eth0 adapter.

### Binding Anonymously

Users can bind to LDAP anonymously through the tool and dump basic information about LDAP, including domain naming context, domain controller hostnames, and more.

<p align="center">
  <img src="https://github.com/dievus/msLDAPDump/blob/main/images/image.png"/>
</p>

### Credentialed Bind

Users can bind to LDAP utilizing valid user account credentials. Using credentials will obtain the same information as the anonymously binded request, as well as checking for the following:

* Users
* Groups
* Kerberoastable Accounts
* ASREPRoastable Accounts
* Constrained Delegation
* Unconstrained Delegation
* Computer Accounts - will also attempt DNS lookups on the hostname to identify IP addresses
* Group Policy Objects (GPO)
* Passwords in User description fields

Each check outputs the raw contents to a text file, and an abbreviated, cleaner version of the results in the terminal environment. The results in the terminal are pulled from the individual text files.

<p align="center">
  <img src="https://github.com/dievus/msLDAPDump/blob/main/images/image.png" width="781" height="560"/>
</p>

### To-Do
- [ ] Add support for LDAPS (LDAP Secure)
- [ ] Figure out why Unix only allows one adapter to make a call out to the LDAP server (removed resolution from Linux until resolved)
