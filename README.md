# msLDAPDump
LDAP enumeration tool implemented in Python3

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M03Q2JN)

msLDAPDump simplifies LDAP enumeration in a domain environment by wrapping the lpap3 library from Python in an easy-to-use interface. 

### Binding Anonymously

Users can bind to LDAP anonymously through the tool and dump basic information about LDAP, including domain naming context, domain controller hostnames, and more.

<p align="center">
  <img src="https://github.com/dievus/msLDAPDump/blob/main/images/image1.png" width="902" height="520"/>
</p>

### Credentialed Bind

Users can bind to LDAP utilizing credentials and a known domain name. Using credentials in the tool will dump the domain naming context as with binding anonymously, and then the user can enter the domain name where required. The tool is currently configured to dump users, computers, and Group Policy Object (GPO) information. If you think the tool could use additional checks please open an issue with the recommendation, and if it makes sense I'll add it.

Results are dumped into a text document in the tool's directory once complete. Opening the tool in something like Notepad++ allows for easy searching of keywords, such as passwords in descriptions.

<p align="center">
  <img src="https://github.com/dievus/msLDAPDump/blob/main/images/image.png" width="781" height="560"/>
</p>

### To-Do
- [ ] Add support for LDAPS (LDAP Secure)
