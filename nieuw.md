# Network Vulnerability Scan Report

**Scantijd:** 2026-05-29 13:25:54  
**Target:** 192.168.178.0/24  
**Modus:** normal  
**Hosts gescand:** 20  

---

## Samenvatting

| Ernst | Bevindingen |
|-------|-------------|
| 🔴 CRITICAL | 6 |
| 🟠 HIGH | 5 |
| 🟡 MEDIUM | 1 |
| 🔵 LOW | 12 |
| ⚪ INFO | 49 |

---

## Bevindingen per host

### 192.168.178.1 — home

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 445/tcp | netbios-ssn | Samba smbd 3.6.25 | 🔴 CRITICAL | Primary vector for EternalBlue/WannaCry/ransomware |
| 139/tcp | netbios-ssn | Samba smbd 3.X - 4.X | 🟠 HIGH | Legacy SMB — frequent malware vector |
| 53/tcp | domain | Cloudflare public DNS | 🟡 MEDIUM | Verify recursive queries are restricted |
| 80/tcp | http | — | 🔵 LOW | Unencrypted — consider HTTPS redirect; nmap script http-vuln-cve2014-3704: see raw output; nmap script http-vuln-cve2017-1001000: see raw output |
| 443/tcp | https | — | ⚪ INFO | Check TLS version and certificate validity; nmap script http-vuln-cve2014-3704: see raw output |
| 3517/tcp | 802-11-iapp | — | ⚪ INFO | — |
| 5000/tcp | upnp | MiniUPnP 2.3.1 | ⚪ INFO | nmap script vulners: see raw output |

<details>
<summary>Script-output</summary>

**fingerprint-strings** op poort 80:

```
GetRequest, HTTPOptions: 
    HTTP/1.1 200 OK
    Content-Type: text/html
    Cache-Control: no-cache
    Last-Modified: Thu, 10 Apr 2025 02:38:49 GMT
    Content-Length: 1461
    Date: Fri, 29 May 2026 11:26:18 GMT
    X-Frame-Options: sameorigin
    Content-Security-Policy: frame-ancestors 'self'
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    <!DOCTYPE html><html><head><meta charset=utf-8><meta http-equiv=Cache-Control content=no-store><meta http-equiv=cache-control content=no-cache><meta http-equiv=cache-control content="max-age=0"><meta name=viewport content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1"><title>.::Welcome to the Web-Based Configurator::.</title><link rel=stylesheet href=./static/plugins/bootstrap-4.0.0/bootstrap.min.css><link rel=stylesheet href=./static/plugins/glyphicons/glyphicons.css><link type=text/css href=./static/plugins/zyxel-icon/styles.css rel=stylesheet><link re
```

**http-title** op poort 80:

```
.::Welcome to the Web-Based Configurator::.
```

**http-vuln-cve2014-3704** op poort 80:

```
ERROR: Script execution failed (use -d to debug)
```

**http-dombased-xss** op poort 80:

```
Couldn't find any DOM based XSS.
```

**http-vuln-cve2017-1001000** op poort 80:

```
ERROR: Script execution failed (use -d to debug)
```

**http-csrf** op poort 80:

```
Couldn't find any CSRF vulnerabilities.
```

**http-phpmyadmin-dir-traversal** op poort 80:

```
VULNERABLE:
  phpMyAdmin grab_globals.lib.php subform Parameter Traversal Local File Inclusion
    State: UNKNOWN (unable to test)
    IDs:  CVE:CVE-2005-3299
      PHP file inclusion vulnerability in grab_globals.lib.php in phpMyAdmin 2.6.4 and 2.6.4-pl1 allows remote attackers to include local files via the $__redirect parameter, possibly involving the subform array.
      
    Disclosure date: 2005-10-nil
    Extra information:
      ../../../../../etc/passwd :
  <!DOCTYPE html><html><head><meta charset=utf-8><meta http-equiv=Cache-Control content=no-store><meta http-equiv=cache-control content=no-cache><meta http-equiv=cache-control content="max-age=0"><meta name=viewport content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1"><title>.::Welcome to the Web-Based Configurator::.</title><link rel=stylesheet href=./static/plugins/bootstrap-4.0.0/bootstrap.min.css><link rel=stylesheet href=./static/plugins/glyphicons/glyphicons.css><link type=text/css href=./static/plugins/zyxel-icon/styles.css rel=stylesheet><link rel=stylesheet href=./static/css/layout.css><link rel=stylesheet href=./static/css/colorTheme.css><link rel=icon href=./static/images/FaviconZyxel.png><link href=/static/css/app.33af2a52be75ac819a9d9557c3a2581e.css rel=stylesheet></head><body><div id=app class=yellow></div><script src=./static/plugins/jquery-3.5.1.slim.min.js></script><script src=./static/plugins/popper/popper.min.js></script><script src=./static/plugins/bootstrap-4.0.0/bootstrap.min.js></script><script src=./static/js/site.js></script><script src=./static/js/zyxel.js></script><script src=./static/js/jsencrypt.min.js></script><script src=./static/js/d3.js></script><script src=./static/js/aes.js></script><script type=text/javascript src=/static/js/manifest.js></script><script type=text/javascript src=/static/js/vendor.js></script><script type=text/javascript src=/static/js/app.js></script></body></html>
    References:
      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3299
      http://www.exploit-db.com/exploits/1244/
```

**http-stored-xss** op poort 80:

```
Couldn't find any stored XSS vulnerabilities.
```

**fingerprint-strings** op poort 443:

```
RTSPRequest: 
    HTTP/1.1 200 OK
    Content-Type: text/html
    Cache-Control: no-cache
    Last-Modified: Thu, 10 Apr 2025 02:38:49 GMT
    Content-Length: 1461
    Date: Fri, 29 May 2026 11:26:34 GMT
    X-Frame-Options: sameorigin
    Content-Security-Policy: frame-ancestors 'self'
    X-Content-Type-Options: nosniff
    X-XSS-Protection: 1; mode=block
    <!DOCTYPE html><html><head><meta charset=utf-8><meta http-equiv=Cache-Control content=no-store><meta http-equiv=cache-control content=no-cache><meta http-equiv=cache-control content="max-age=0"><meta name=viewport content="width=device-width,initial-scale=1,minimum-scale=1,maximum-scale=1"><title>.::Welcome to the Web-Based Configurator::.</title><link rel=stylesheet href=./static/plugins/bootstrap-4.0.0/bootstrap.min.css><link rel=stylesheet href=./static/plugins/glyphicons/glyphicons.css><link type=text/css href=./static/plugins/zyxel-icon/styles.css rel=stylesheet><link re
```

**ssl-cert** op poort 443:

```
Subject: commonName=ZyXELcert/organizationName=ZyXEL/stateOrProvinceName=TWN/countryName=TW
Not valid before: 2023-04-13T00:00:20
Not valid after:  2033-04-10T00:00:20
```

**ssl-date** op poort 443:

```
TLS randomness does not represent time
```

**http-aspnet-debug** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**sstp-discover** op poort 443:

```
SSTP is supported.
```

**http-vuln-cve2014-3704** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-enum** op poort 443:

```
/blog/: Blog
  /weblog/: Blog
```

**http-stored-xss** op poort 443:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-dombased-xss** op poort 443:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 443:

```
Couldn't find any CSRF vulnerabilities.
```

**fingerprint-strings** op poort 5000:

```
FourOhFourRequest: 
    HTTP/1.0 404 Not Found
    Content-Type: text/html
    Connection: close
    Content-Length: 134
    Server: OpenWrt/5.4.171 UPnP/1.1 MiniUPnPd/2.3.1
    Ext:
    Date: Fri, 29 May 2026 11:26:28 GMT
    <HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>Not Found</H1>The requested URL was not found on this server.</BODY></HTML>
  GenericLines: 
    501 Not Implemented
    Content-Type: text/html
    Connection: close
    Content-Length: 149
    Server: OpenWrt/5.4.171 UPnP/1.1 MiniUPnPd/2.3.1
    Ext:
    Date: Fri, 29 May 2026 11:26:18 GMT
    <HTML><HEAD><TITLE>501 Not Implemented</TITLE></HEAD><BODY><H1>Not Implemented</H1>The HTTP Method is not implemented by this server.</BODY></HTML>
  GetRequest: 
    HTTP/1.0 404 Not Found
    Content-Type: text/html
    Connection: close
    Content-Length: 134
    Server: OpenWrt/5.4.171 UPnP/1.1 MiniUPnPd/2.3.1
    Ext:
    Date: Fri, 29 May 2026 11:26:18 GMT
    <HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>Not Found</H1>The requested URL was not found on this server.</BODY></HTML>
  HTTPOptions: 
    HTTP/1.0 501 Not Implemented
    Content-Type: text/html
```

**vulners** op poort 5000:

```
cpe:/a:miniupnp_project:miniupnpd:2.3.1: 
    	CVE-2026-5720	9.1	https://vulners.com/cve/CVE-2026-5720
```

</details>

---

### 192.168.178.15 — Google-Home.home

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 8443/tcp | https-alt | — | 🔵 LOW | Check TLS and exposed services |
| 8008/tcp | http | — | ⚪ INFO | — |
| 8009/tcp | ajp13 | — | ⚪ INFO | — |
| 9000/tcp | cslistener | — | ⚪ INFO | — |
| 10001/tcp | scp-config | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**ssl-cert** op poort 8443:

```
Subject: commonName=AXT8QZ FA8FCA538779/organizationName=Google Inc/stateOrProvinceName=California/countryName=US
Not valid before: 2017-03-12T07:15:24
Not valid after:  2037-03-07T07:15:24
```

**ssl-date** op poort 8443:

```
2026-05-29T11:42:54+00:00; +1s from scanner time.
```

**http-title** op poort 8443:

```
Site doesn't have a title.
```

**http-title** op poort 8008:

```
Site doesn't have a title.
```

**http-csrf** op poort 8008:

```
Couldn't find any CSRF vulnerabilities.
```

**http-stored-xss** op poort 8008:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-dombased-xss** op poort 8008:

```
Couldn't find any DOM based XSS.
```

**ajp-methods** op poort 8009:

```
Failed to get a valid response for the OPTION request
```

**ssl-date** op poort 8009:

```
TLS randomness does not represent time
```

**ssl-cert** op poort 8009:

```
Subject: commonName=8f891e18-c66b-23bd-dcd3-7e0914cc00ac
Not valid before: 2026-05-28T14:25:53
Not valid after:  2026-05-30T14:25:53
```

**ssl-ccs-injection** op poort 9000:

```
No reply from server (TIMEOUT)
```

**ssl-date** op poort 10001:

```
2026-05-29T11:42:54+00:00; +1s from scanner time.
```

</details>

---

### 192.168.178.16 — lenovo.home

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 8443/tcp | https-alt | — | 🔵 LOW | Check TLS and exposed services |
| 8008/tcp | http | — | ⚪ INFO | — |
| 8009/tcp | ajp13 | — | ⚪ INFO | — |
| 9000/tcp | cslistener | — | ⚪ INFO | — |
| 10001/tcp | scp-config | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**ssl-date** op poort 8443:

```
2026-05-29T11:50:40+00:00; 0s from scanner time.
```

**ssl-cert** op poort 8443:

```
Subject: commonName=15309A7E5F6E6D44BCF6 FA:8F:CA:62:F3:A0
Not valid before: 2020-04-11T07:52:45
Not valid after:  2040-04-06T07:52:45
```

**http-title** op poort 8443:

```
Site doesn't have a title.
```

**http-dombased-xss** op poort 8008:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 8008:

```
Couldn't find any CSRF vulnerabilities.
```

**http-title** op poort 8008:

```
Site doesn't have a title.
```

**http-stored-xss** op poort 8008:

```
Couldn't find any stored XSS vulnerabilities.
```

**ajp-methods** op poort 8009:

```
Failed to get a valid response for the OPTION request
```

**ssl-date** op poort 8009:

```
TLS randomness does not represent time
```

**ssl-cert** op poort 8009:

```
Subject: commonName=d663f463-e236-0c94-314e-8aee58df349d
Not valid before: 2026-05-28T14:44:59
Not valid after:  2026-05-30T14:44:59
```

**ssl-date** op poort 9000:

```
2026-05-29T11:50:40+00:00; 0s from scanner time.
```

**ssl-date** op poort 10001:

```
2026-05-29T11:50:40+00:00; +1s from scanner time.
```

</details>

---

### 192.168.178.19 — Google-Home-Mini.home

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 8443/tcp | https-alt | — | 🔵 LOW | Check TLS and exposed services |
| 8008/tcp | http | — | ⚪ INFO | — |
| 8009/tcp | ajp13 | — | ⚪ INFO | — |
| 9000/tcp | cslistener | — | ⚪ INFO | — |
| 10001/tcp | scp-config | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**ssl-cert** op poort 8443:

```
Subject: commonName=L27EIT FA8FCA9786AF/organizationName=Google Inc/stateOrProvinceName=California/countryName=US
Not valid before: 2018-08-03T20:01:01
Not valid after:  2038-07-29T20:01:01
```

**ssl-date** op poort 8443:

```
2026-05-29T11:56:23+00:00; +1s from scanner time.
```

**http-title** op poort 8443:

```
Site doesn't have a title.
```

**http-dombased-xss** op poort 8008:

```
Couldn't find any DOM based XSS.
```

**http-title** op poort 8008:

```
Site doesn't have a title.
```

**http-csrf** op poort 8008:

```
Couldn't find any CSRF vulnerabilities.
```

**http-stored-xss** op poort 8008:

```
Couldn't find any stored XSS vulnerabilities.
```

**ssl-cert** op poort 8009:

```
Subject: commonName=d6f6fef6-1d47-f33a-1919-1a81ca42d3a1
Not valid before: 2026-05-28T14:15:30
Not valid after:  2026-05-30T14:15:30
```

**ssl-date** op poort 8009:

```
TLS randomness does not represent time
```

**ajp-methods** op poort 8009:

```
Failed to get a valid response for the OPTION request
```

**ssl-ccs-injection** op poort 9000:

```
No reply from server (TIMEOUT)
```

**ssl-date** op poort 10001:

```
2026-05-29T11:56:23+00:00; 0s from scanner time.
```

</details>

---

### 192.168.178.20

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 8443/tcp | https-alt | — | 🔵 LOW | Check TLS and exposed services; nmap script http-vuln-cve2014-3704: see raw output |
| 8008/tcp | http | — | ⚪ INFO | — |
| 8009/tcp | ajp13 | — | ⚪ INFO | — |
| 9000/tcp | cslistener | — | ⚪ INFO | — |
| 10001/tcp | scp-config | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**ssl-ccs-injection** op poort 8443:

```
No reply from server (TIMEOUT)
```

**http-title** op poort 8443:

```
Site doesn't have a title (text/html).
```

**http-aspnet-debug** op poort 8443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-vuln-cve2014-3704** op poort 8443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-title** op poort 8008:

```
Site doesn't have a title (text/html).
```

**http-csrf** op poort 8008:

```
Couldn't find any CSRF vulnerabilities.
```

**http-dombased-xss** op poort 8008:

```
Couldn't find any DOM based XSS.
```

**http-stored-xss** op poort 8008:

```
Couldn't find any stored XSS vulnerabilities.
```

**ssl-date** op poort 8009:

```
TLS randomness does not represent time
```

**ssl-cert** op poort 8009:

```
Subject: commonName=bf09e3ce-c1e1-f83e-aba1-fd3fabfdc450
Not valid before: 2026-05-28T22:56:48
Not valid after:  2026-05-30T22:56:48
```

**ajp-methods** op poort 8009:

```
Failed to get a valid response for the OPTION request
```

**ssl-date** op poort 9000:

```
2026-05-29T12:00:33+00:00; 0s from scanner time.
```

**ssl-date** op poort 10001:

```
2026-05-29T12:00:33+00:00; 0s from scanner time.
```

</details>

---

### 192.168.178.40

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 23/tcp | telnet | — | 🔴 CRITICAL | Unencrypted remote shell — replace with SSH immediately |
| 80/tcp | http | nginx | 🔴 CRITICAL | Unencrypted — consider HTTPS redirect; nmap script http-vuln-cve2011-3192: potential vulnerability detected |
| 443/tcp | http | nginx | 🔴 CRITICAL | Check TLS version and certificate validity; nmap script http-vuln-cve2011-3192: potential vulnerability detected |
| 445/tcp | netbios-ssn | Samba smbd 3.X - 4.X | 🔴 CRITICAL | Primary vector for EternalBlue/WannaCry/ransomware |
| 139/tcp | netbios-ssn | Samba smbd 3.X - 4.X | 🟠 HIGH | Legacy SMB — frequent malware vector |
| 22/tcp | ssh | OpenSSH 8.2 | ⚪ INFO | Ensure key-based auth; disable root login; nmap script vulners: see raw output |
| 548/tcp | afp | Netatalk 3.1.12 | ⚪ INFO | nmap script vulners: see raw output |
| 5000/tcp | http | nginx | ⚪ INFO | — |
| 5001/tcp | http | nginx | ⚪ INFO | — |
| 5357/tcp | http | nginx | ⚪ INFO | — |
| 49160/tcp | upnp | Portable SDK for UPnP 1.12.1 | ⚪ INFO | nmap script vulners: see raw output |

<details>
<summary>Script-output</summary>

**http-title** op poort 80:

```
Wie ben jij? \xE2\x80\x94 Synology Startpagina
```

**http-vuln-cve2011-3192** op poort 80:

```
VULNERABLE:
  Apache byterange filter DoS
    State: VULNERABLE
    IDs:  BID:49303  CVE:CVE-2011-3192
      The Apache web server is vulnerable to a denial of service attack when numerous
      overlapping byte ranges are requested.
    Disclosure date: 2011-08-19
    References:
      https://seclists.org/fulldisclosure/2011/Aug/175
      https://www.tenable.com/plugins/nessus/55976
      https://www.securityfocus.com/bid/49303
      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
```

**http-stored-xss** op poort 80:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-dombased-xss** op poort 80:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 80:

```
Couldn't find any CSRF vulnerabilities.
```

**ssl-date** op poort 443:

```
TLS randomness does not represent time
```

**ssl-cert** op poort 443:

```
Subject: commonName=synology.com/organizationName=Synology Inc./stateOrProvinceName=Taiwan/countryName=TW
Subject Alternative Name: email:product@synology.com
Not valid before: 2015-11-03T18:06:41
Not valid after:  2035-07-21T18:06:41
```

**http-dombased-xss** op poort 443:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 443:

```
Couldn't find any CSRF vulnerabilities.
```

**http-title** op poort 443:

```
Site doesn't have a title (text/html).
```

**http-stored-xss** op poort 443:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-vuln-cve2011-3192** op poort 443:

```
VULNERABLE:
  Apache byterange filter DoS
    State: VULNERABLE
    IDs:  BID:49303  CVE:CVE-2011-3192
      The Apache web server is vulnerable to a denial of service attack when numerous
      overlapping byte ranges are requested.
    Disclosure date: 2011-08-19
    References:
      https://seclists.org/fulldisclosure/2011/Aug/175
      https://www.tenable.com/plugins/nessus/55976
      https://www.securityfocus.com/bid/49303
      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
```

**ssh-hostkey** op poort 22:

```
2048 8b:32:60:24:bb:9b:9b:e4:f2:0f:b2:3b:b9:4a:4a:7f (RSA)
  256 a8:06:6f:94:34:ad:3e:ab:63:2c:50:aa:62:9e:66:20 (ECDSA)
  256 4e:5b:89:0e:5f:cb:08:ba:3d:ca:f6:fd:4a:ba:10:76 (ED25519)
```

**vulners** op poort 22:

```
cpe:/a:openbsd:openssh:8.2: 
    	PACKETSTORM:173661	9.8	https://vulners.com/packetstorm/PACKETSTORM:173661	*EXPLOIT*
    	F0979183-AE88-53B4-86CF-3AF0523F3807	9.8	https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807	*EXPLOIT*
    	CVE-2023-38408	9.8	https://vulners.com/cve/CVE-2023-38408
    	B8190CDB-3EB9-5631-9828-8064A1575B23	9.8	https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23	*EXPLOIT*
    	A2B36B85-C737-548F-8C04-9339EDCDBFF5	9.8	https://vulners.com/githubexploit/A2B36B85-C737-548F-8C04-9339EDCDBFF5	*EXPLOIT*
    	8FC9C5AB-3968-5F3C-825E-E8DB5379A623	9.8	https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623	*EXPLOIT*
    	8AD01159-548E-546E-AA87-2DE89F3927EC	9.8	https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC	*EXPLOIT*
    	6192C35D-F78B-5C0A-AB8D-9826A79A5320	9.8	https://vulners.com/githubexploit/6192C35D-F78B-5C0A-AB8D-9826A79A5320	*EXPLOIT*
    	2227729D-6700-5C8F-8930-1EEAFD4B9FF0	9.8	https://vulners.com/githubexploit/2227729D-6700-5C8F-8930-1EEAFD4B9FF0	*EXPLOIT*
    	0221525F-07F5-5790-912D-F4B9E2D1B587	9.8	https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587	*EXPLOIT*
    	CVE-2026-35414	8.1	https://vulners.com/cve/CVE-2026-35414
    	CVE-2026-35386	8.1	https://vulners.com/cve/CVE-2026-35386
    	CVE-2026-35385	8.1	https://vulners.com/cve/CVE-2026-35385
    	BA3887BD-F579-53B1-A4A4-FF49E953E1C0	8.1	https://vulners.com/githubexploit/BA3887BD-F579-53B1-A4A4-FF49E953E1C0	*EXPLOIT*
    	4FB01B00-F993-5CAF-BD57-D7E290D10C1F	8.1	https://vulners.com/githubexploit/4FB01B00-F993-5CAF-BD57-D7E290D10C1F	*EXPLOIT*
    	CVE-2020-15778	7.8	https://vulners.com/cve/CVE-2020-15778
    	C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	7.8	https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3	*EXPLOIT*
    	991D2CC4-0E09-5745-97A2-4917461BD6EC	7.8	https://vulners.com/githubexploit/991D2CC4-0E09-5745-97A2-4917461BD6EC	*EXPLOIT*
    	2E719186-2FED-58A8-A150-762EFBAAA523	7.8	https://vulners.com/gitee/2E719186-2FED-58A8-A150-762EFBAAA523	*EXPLOIT*
    	23CC97BE-7C95-513B-9E73-298C48D74432	7.8	https://vulners.com/githubexploit/23CC97BE-7C95-513B-9E73-298C48D74432	*EXPLOIT*
    	10213DBE-F683-58BB-B6D3-353173626207	7.8	https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207	*EXPLOIT*
    	SSV:92579	7.5	https://vulners.com/seebug/SSV:92579	*EXPLOIT*
    	CVE-2020-12062	7.5	https://vulners.com/cve/CVE-2020-12062
    	CNVD-2020-36277	7.5	https://vulners.com/cnvd/CNVD-2020-36277
    	1337DAY-ID-26576	7.5	https://vulners.com/zdt/1337DAY-ID-26576	*EXPLOIT*
    	CVE-2021-28041	7.1	https://vulners.com/cve/CVE-2021-28041
    	CVE-2021-41617	7.0	https://vulners.com/cve/CVE-2021-41617
    	284B94FC-FD5D-5C47-90EA-47900DAD1D1E	7.0	https://vulners.com/githubexploit/284B94FC-FD5D-5C47-90EA-47900DAD1D1E	*EXPLOIT*
    	PACKETSTORM:189283	6.8	https://vulners.com/packetstorm/PACKETSTORM:189283	*EXPLOIT*
```

**afp-serverinfo** op poort 548:

```
Server Flags: 
    Flags hex: 0x8f79
    Super Client: true
    UUIDs: true
    UTF8 Server Name: true
    Open Directory: true
    Reconnect: false
    Server Notifications: true
    TCP/IP: true
    Server Signature: true
    Server Messages: true
    Password Saving Prohibited: false
    Password Changing: false
    Copy File: true
  Server Name: TM-DS215J
  Machine Type: Netatalk3.1.12
  AFP Versions: AFP2.2, AFPX03, AFP3.1, AFP3.2, AFP3.3, AFP3.4
  UAMs: DHX2, DHCAST128
  Server Signature: 61c4f8a9be9bff4c7caff08e5379f088
  Network Addresses: 
    192.168.178.40
  UTF8 Server Name: TM-DS215J
```

**vulners** op poort 548:

```
cpe:/a:netatalk:netatalk:3.1.12: 
    	PACKETSTORM:152440	10.0	https://vulners.com/packetstorm/PACKETSTORM:152440	*EXPLOIT*
    	EXPLOITPACK:78BE2C4104635132850FD0BCCC25D5B2	10.0	https://vulners.com/exploitpack/EXPLOITPACK:78BE2C4104635132850FD0BCCC25D5B2	*EXPLOIT*
    	EXPLOITPACK:6B2C2435AB5BEEDB8A3568179F877759	10.0	https://vulners.com/exploitpack/EXPLOITPACK:6B2C2435AB5BEEDB8A3568179F877759	*EXPLOIT*
    	EDB-ID:46675	10.0	https://vulners.com/exploitdb/EDB-ID:46675	*EXPLOIT*
    	EDB-ID:46034	10.0	https://vulners.com/exploitdb/EDB-ID:46034	*EXPLOIT*
    	CVE-2022-22995	10.0	https://vulners.com/cve/CVE-2022-22995
    	CNVD-2018-26796	10.0	https://vulners.com/cnvd/CNVD-2018-26796
    	2FA90A6C-7FC3-55DE-B830-7523ECBE089E	10.0	https://vulners.com/githubexploit/2FA90A6C-7FC3-55DE-B830-7523ECBE089E	*EXPLOIT*
    	1337DAY-ID-32501	10.0	https://vulners.com/zdt/1337DAY-ID-32501	*EXPLOIT*
    	1337DAY-ID-31826	10.0	https://vulners.com/zdt/1337DAY-ID-31826	*EXPLOIT*
    	CVE-2024-38441	9.8	https://vulners.com/cve/CVE-2024-38441
    	CVE-2024-38439	9.8	https://vulners.com/cve/CVE-2024-38439
    	CVE-2023-42464	9.8	https://vulners.com/cve/CVE-2023-42464
    	CVE-2022-43634	9.8	https://vulners.com/cve/CVE-2022-43634
    	CVE-2022-23125	9.8	https://vulners.com/cve/CVE-2022-23125
    	CVE-2022-23124	9.8	https://vulners.com/cve/CVE-2022-23124
    	CVE-2022-23123	9.8	https://vulners.com/cve/CVE-2022-23123
    	CVE-2022-23122	9.8	https://vulners.com/cve/CVE-2022-23122
    	CVE-2022-23121	9.8	https://vulners.com/cve/CVE-2022-23121
    	CVE-2022-0194	9.8	https://vulners.com/cve/CVE-2022-0194
    	CVE-2021-31439	8.8	https://vulners.com/cve/CVE-2021-31439
    	CVE-2022-45188	7.8	https://vulners.com/cve/CVE-2022-45188
    	CVE-2024-38440	7.5	https://vulners.com/cve/CVE-2024-38440
    	PACKETSTORM:150891	0.0	https://vulners.com/packetstorm/PACKETSTORM:150891	*EXPLOIT*
```

**http-sql-injection** op poort 5000:

```
ERROR: Script execution failed (use -d to debug)
```

**http-stored-xss** op poort 5000:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-dombased-xss** op poort 5000:

```
Couldn't find any DOM based XSS.
```

**http-slowloris-check** op poort 5000:

```
VULNERABLE:
  Slowloris DOS attack
    State: LIKELY VULNERABLE
    IDs:  CVE:CVE-2007-6750
      Slowloris tries to keep many connections to the target web server open and hold
      them open as long as possible.  It accomplishes this by opening connections to
      the target web server and sending a partial request. By doing so, it starves
      the http server's resources causing Denial Of Service.
      
    Disclosure date: 2009-09-17
    References:
      http://ha.ckers.org/slowloris/
      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
```

**http-enum** op poort 5000:

```
/robots.txt: Robots file
```

**http-csrf** op poort 5000:

```
Couldn't find any CSRF vulnerabilities.
```

**http-title** op poort 5000:

```
TM-DS215J&nbsp;-&nbsp;Synology&nbsp;DiskStation
```

**http-robots.txt** op poort 5000:

```
1 disallowed entry 
/
```

**http-stored-xss** op poort 5001:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-csrf** op poort 5001:

```
Couldn't find any CSRF vulnerabilities.
```

**http-dombased-xss** op poort 5001:

```
Couldn't find any DOM based XSS.
```

**http-title** op poort 5001:

```
400 The plain HTTP request was sent to HTTPS port
```

**http-sql-injection** op poort 5001:

```
ERROR: Script execution failed (use -d to debug)
```

**http-enum** op poort 5001:

```
/robots.txt: Robots file
```

**ssl-date** op poort 5001:

```
TLS randomness does not represent time
```

**ssl-cert** op poort 5001:

```
Subject: commonName=synology.com/organizationName=Synology Inc./stateOrProvinceName=Taiwan/countryName=TW
Subject Alternative Name: email:product@synology.com
Not valid before: 2015-11-03T18:06:41
Not valid after:  2035-07-21T18:06:41
```

**http-robots.txt** op poort 5001:

```
1 disallowed entry 
/
```

**http-slowloris-check** op poort 5357:

```
VULNERABLE:
  Slowloris DOS attack
    State: LIKELY VULNERABLE
    IDs:  CVE:CVE-2007-6750
      Slowloris tries to keep many connections to the target web server open and hold
      them open as long as possible.  It accomplishes this by opening connections to
      the target web server and sending a partial request. By doing so, it starves
      the http server's resources causing Denial Of Service.
      
    Disclosure date: 2009-09-17
    References:
      http://ha.ckers.org/slowloris/
      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
```

**http-dombased-xss** op poort 5357:

```
Couldn't find any DOM based XSS.
```

**http-stored-xss** op poort 5357:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-title** op poort 5357:

```
502 Bad Gateway
```

**http-csrf** op poort 5357:

```
Couldn't find any CSRF vulnerabilities.
```

**vulners** op poort 49160:

```
cpe:/o:linux:linux_kernel:3.2.101: 
    	PACKETSTORM:167805	10.0	https://vulners.com/packetstorm/PACKETSTORM:167805	*EXPLOIT*
    	PACKETSTORM:155267	10.0	https://vulners.com/packetstorm/PACKETSTORM:155267	*EXPLOIT*
    	EXPLOITPACK:CDE6BEFB491AF8EAA191AB4CAF1FFA98	10.0	https://vulners.com/exploitpack/EXPLOITPACK:CDE6BEFB491AF8EAA191AB4CAF1FFA98	*EXPLOIT*
    	EDB-ID:47625	10.0	https://vulners.com/exploitdb/EDB-ID:47625	*EXPLOIT*
    	DEE8E854-A0E9-55E3-99A4-DACDE0E030EB	10.0	https://vulners.com/gitee/DEE8E854-A0E9-55E3-99A4-DACDE0E030EB	*EXPLOIT*
    	CVE-2019-15505	10.0	https://vulners.com/cve/CVE-2019-15505
    	CVE-2019-15292	10.0	https://vulners.com/cve/CVE-2019-15292
    	CVE-2019-14896	10.0	https://vulners.com/cve/CVE-2019-14896
    	CVE-2015-8104	10.0	https://vulners.com/cve/CVE-2015-8104
    	9620C0F1-939A-5E96-8E33-10DF47A94D57	10.0	https://vulners.com/githubexploit/9620C0F1-939A-5E96-8E33-10DF47A94D57	*EXPLOIT*
    	8DF4117A-0CBF-5767-BEB0-31D3E0375D32	10.0	https://vulners.com/githubexploit/8DF4117A-0CBF-5767-BEB0-31D3E0375D32	*EXPLOIT*
    	894728CC-90FB-5FEA-99F3-C2EEFD32B4C3	10.0	https://vulners.com/gitee/894728CC-90FB-5FEA-99F3-C2EEFD32B4C3	*EXPLOIT*
    	86A8C314-EBCC-5D85-9D5C-608998FC764F	10.0	https://vulners.com/githubexploit/86A8C314-EBCC-5D85-9D5C-608998FC764F	*EXPLOIT*
    	45A567A8-CA13-5007-A163-A263F598BC6C	10.0	https://vulners.com/githubexploit/45A567A8-CA13-5007-A163-A263F598BC6C	*EXPLOIT*
    	2790F5AF-5EDF-52F3-BC69-1380E2AE0DB4	10.0	https://vulners.com/githubexploit/2790F5AF-5EDF-52F3-BC69-1380E2AE0DB4	*EXPLOIT*
    	1337DAY-ID-37859	10.0	https://vulners.com/zdt/1337DAY-ID-37859	*EXPLOIT*
    	1337DAY-ID-33499	10.0	https://vulners.com/zdt/1337DAY-ID-33499	*EXPLOIT*
    	ZSL-2019-5526	9.8	https://vulners.com/zeroscience/ZSL-2019-5526	*EXPLOIT*
    	EDB-ID:44806	9.8	https://vulners.com/exploitdb/EDB-ID:44806	*EXPLOIT*
    	CVE-2026-43493	9.8	https://vulners.com/cve/CVE-2026-43493
    	CVE-2026-43198	9.8	https://vulners.com/cve/CVE-2026-43198
    	CVE-2026-43037	9.8	https://vulners.com/cve/CVE-2026-43037
    	CVE-2026-43011	9.8	https://vulners.com/cve/CVE-2026-43011
    	CVE-2026-31649	9.8	https://vulners.com/cve/CVE-2026-31649
    	CVE-2026-31637	9.8	https://vulners.com/cve/CVE-2026-31637
    	CVE-2026-31609	9.8	https://vulners.com/cve/CVE-2026-31609
    	CVE-2026-31608	9.8	https://vulners.com/cve/CVE-2026-31608
    	CVE-2026-31607	9.8	https://vulners.com/cve/CVE-2026-31607
    	CVE-2026-31414	9.8	https://vulners.com/cve/CVE-2026-31414
```

</details>

---

### 192.168.178.45 — BRW105BAD6F72BF.home

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 80/tcp | http | — | 🔵 LOW | Unencrypted — consider HTTPS redirect |
| 443/tcp | https | — | ⚪ INFO | Check TLS version and certificate validity; nmap script http-vuln-cve2014-3704: see raw output |
| 515/tcp | printer | — | ⚪ INFO | — |
| 631/tcp | ipp | — | ⚪ INFO | nmap script http-vuln-wnr1000-creds: see raw output |
| 9100/tcp | jetdirect | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**fingerprint-strings** op poort 80:

```
GetRequest: 
    HTTP/1.1 301 Moved Permanently
    Cache-Control: no-cache
    X-Frame-Options: DENY
    Content-Length: 0
    Connection: close
    Pragma: no-cache
    Location: /general/index.html
  HTTPOptions: 
    HTTP/1.1 411 Length Required
    Cache-Control: no-cache
    X-Frame-Options: DENY
    Content-Length: 974
    Content-Type: text/html
    Connection: close
    Pragma: no-cache
    <html>
    <head>
    <title>HTTP status</title>
    <style type="text/css">
    body
    margin-top: 30px;
    margin-right: 5%;
    margin-left: 5%;
    background-color: #ffffff;
    color: #000000;
    font-family: serif;
    font-size: 12px;
    line-height: 150%;
    .header
```

**http-robots.txt** op poort 80:

```
1 disallowed entry 
/
```

**http-title** op poort 80:

```
Brother MFC-J497DW
Requested resource was /general/index.html
```

**http-sql-injection** op poort 80:

```
ERROR: Script execution failed (use -d to debug)
```

**http-dombased-xss** op poort 80:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 80:

```
Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=BRW105BAD6F72BF.home
  Found the following possible CSRF vulnerabilities: 
    
    Path: http://BRW105BAD6F72BF.home:80/
    Form id: logbox
    Form action: /general/status.html
    
    Path: http://BRW105BAD6F72BF.home:80/general/status.html
    Form id: logbox
    Form action: /general/status.html
    
    Path: http://BRW105BAD6F72BF.home:80/general/status.html
    Form id: pageid
    Form action: /general/status.html
    
    Path: http://BRW105BAD6F72BF.home:80/general/index.html
    Form id: logbox
    Form action: /general/status.html
    
    Path: http://BRW105BAD6F72BF.home:80/general/status.html?pageid=1
    Form id: logbox
    Form action: /general/status.html
    
    Path: http://BRW105BAD6F72BF.home:80/general/status.html?pageid=1
    Form id: pageid
    Form action: /general/status.html
```

**http-stored-xss** op poort 80:

```
Couldn't find any stored XSS vulnerabilities.
```

**fingerprint-strings** op poort 443:

```
FourOhFourRequest: 
    HTTP/1.1 404 Not Found
    Cache-Control: no-cache
    X-Frame-Options: DENY
    Content-Length: 942
    Content-Type: text/html
    Connection: close
    Pragma: no-cache
    <html>
    <head>
    <title>HTTP status</title>
    <style type="text/css">
    body
    margin-top: 30px;
    margin-right: 5%;
    margin-left: 5%;
    background-color: #ffffff;
    color: #000000;
    font-family: serif;
    font-size: 12px;
    line-height: 150%;
    .header
    color: #808080;
    font-family: 'Arial Black', sans-serif;
    font-size: 42px;
    line-height: 100%;
    border-bottom: 2px solid #808080;
    margin-bottom: 30px;
    .caps
    color: #e00000;
```

**ssl-cert** op poort 443:

```
Subject: commonName=Preset Certificate
Not valid before: 2000-01-01T00:00:00
Not valid after:  2049-12-30T23:59:59
```

**http-aspnet-debug** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-vuln-cve2014-3704** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-csrf** op poort 443:

```
Couldn't find any CSRF vulnerabilities.
```

**http-dombased-xss** op poort 443:

```
Couldn't find any DOM based XSS.
```

**http-stored-xss** op poort 443:

```
Couldn't find any stored XSS vulnerabilities.
```

**fingerprint-strings** op poort 631:

```
GetRequest: 
    HTTP/1.1 301 Moved Permanently
    Cache-Control: no-cache
    X-Frame-Options: DENY
    Content-Length: 0
    Connection: close
    Pragma: no-cache
    Location: /general/index.html
  HTTPOptions: 
    HTTP/1.1 400 Bad Request
    Cache-Control: no-cache
    X-Frame-Options: DENY
    Content-Length: 965
    Content-Type: text/html
    Connection: close
    Pragma: no-cache
    <html>
    <head>
    <title>HTTP status</title>
    <style type="text/css">
    body
    margin-top: 30px;
    margin-right: 5%;
    margin-left: 5%;
    background-color: #ffffff;
    color: #000000;
    font-family: serif;
    font-size: 12px;
    line-height: 150%;
    .header
```

**http-title** op poort 631:

```
Brother MFC-J497DW
Requested resource was /general/index.html
```

**http-robots.txt** op poort 631:

```
1 disallowed entry 
/
```

**http-vuln-wnr1000-creds** op poort 631:

```
ERROR: Script execution failed (use -d to debug)
```

</details>

---

### 192.168.178.52 — deco-M5.home

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 80/tcp | http | OpenWrt uHTTPd | 🔵 LOW | Unencrypted — consider HTTPS redirect |
| 443/tcp | https | — | ⚪ INFO | Check TLS version and certificate validity; nmap script http-vuln-cve2014-3704: see raw output |

<details>
<summary>Script-output</summary>

**http-title** op poort 80:

```
Site doesn't have a title (text/html).
```

**http-stored-xss** op poort 80:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-csrf** op poort 80:

```
Couldn't find any CSRF vulnerabilities.
```

**http-dombased-xss** op poort 80:

```
Couldn't find any DOM based XSS.
```

**ssl-cert** op poort 443:

```
Subject: commonName=tplinkdeco.net/countryName=CN
Not valid before: 2010-01-01T00:00:00
Not valid after:  2030-12-31T00:00:00
```

**ssl-date** op poort 443:

```
TLS randomness does not represent time
```

**http-aspnet-debug** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-slowloris-check** op poort 443:

```
VULNERABLE:
  Slowloris DOS attack
    State: LIKELY VULNERABLE
    IDs:  CVE:CVE-2007-6750
      Slowloris tries to keep many connections to the target web server open and hold
      them open as long as possible.  It accomplishes this by opening connections to
      the target web server and sending a partial request. By doing so, it starves
      the http server's resources causing Denial Of Service.
      
    Disclosure date: 2009-09-17
    References:
      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
      http://ha.ckers.org/slowloris/
```

**http-csrf** op poort 443:

```
Couldn't find any CSRF vulnerabilities.
```

**http-dombased-xss** op poort 443:

```
Couldn't find any DOM based XSS.
```

**http-stored-xss** op poort 443:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-vuln-cve2014-3704** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

</details>

---

### 192.168.178.53

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 8443/tcp | https-alt | — | 🔵 LOW | Check TLS and exposed services; nmap script http-vuln-cve2014-3704: see raw output |
| 8008/tcp | http | — | ⚪ INFO | — |
| 9000/tcp | cslistener | — | ⚪ INFO | — |
| 10001/tcp | scp-config | — | ⚪ INFO | — |
| 10010/tcp | rxapi | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**ssl-cert** op poort 8443:

```
Subject: commonName=DA0X0T3 FA8FCA3FC5C3/organizationName=Google Inc/stateOrProvinceName=California/countryName=US
Not valid before: 2019-03-05T08:00:00
Not valid after:  2040-12-11T19:03:40
```

**ssl-date** op poort 8443:

```
2026-05-29T12:25:34+00:00; 0s from scanner time.
```

**http-vuln-cve2014-3704** op poort 8443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-aspnet-debug** op poort 8443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-title** op poort 8008:

```
Site doesn't have a title (text/html).
```

**http-csrf** op poort 8008:

```
Couldn't find any CSRF vulnerabilities.
```

**http-dombased-xss** op poort 8008:

```
Couldn't find any DOM based XSS.
```

**http-stored-xss** op poort 8008:

```
Couldn't find any stored XSS vulnerabilities.
```

**ssl-ccs-injection** op poort 9000:

```
No reply from server (TIMEOUT)
```

**ssl-date** op poort 10001:

```
2026-05-29T12:25:34+00:00; +1s from scanner time.
```

</details>

---

### 192.168.178.64

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 80/tcp | http | OpenWrt uHTTPd | 🔵 LOW | Unencrypted — consider HTTPS redirect |
| 443/tcp | https | — | ⚪ INFO | Check TLS version and certificate validity; nmap script http-vuln-cve2014-3704: see raw output |

<details>
<summary>Script-output</summary>

**http-title** op poort 80:

```
Site doesn't have a title (text/html).
```

**http-csrf** op poort 80:

```
Couldn't find any CSRF vulnerabilities.
```

**http-dombased-xss** op poort 80:

```
Couldn't find any DOM based XSS.
```

**http-stored-xss** op poort 80:

```
Couldn't find any stored XSS vulnerabilities.
```

**ssl-cert** op poort 443:

```
Subject: commonName=tplinkdeco.net/countryName=CN
Not valid before: 2010-01-01T00:00:00
Not valid after:  2030-12-31T00:00:00
```

**ssl-date** op poort 443:

```
TLS randomness does not represent time
```

**http-vuln-cve2014-3704** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-aspnet-debug** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-dombased-xss** op poort 443:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 443:

```
Couldn't find any CSRF vulnerabilities.
```

**http-stored-xss** op poort 443:

```
Couldn't find any stored XSS vulnerabilities.
```

</details>

---

### 192.168.178.90 — blink-sync-module.home

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 443/tcp | https | — | ⚪ INFO | Check TLS version and certificate validity; nmap script http-vuln-cve2014-3704: see raw output |

<details>
<summary>Script-output</summary>

**ssl-cert** op poort 443:

```
Subject: commonName=lcc.immedia-semi.com/organizationName=Blink/stateOrProvinceName=MA/countryName=US
Not valid before: 2025-10-29T15:20:00
Not valid after:  2026-10-29T15:20:00
```

**ssl-date** op poort 443:

```
2026-05-29T12:38:11+00:00; 0s from scanner time.
```

**http-vuln-cve2014-3704** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-aspnet-debug** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-dombased-xss** op poort 443:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 443:

```
Couldn't find any CSRF vulnerabilities.
```

**http-stored-xss** op poort 443:

```
Couldn't find any stored XSS vulnerabilities.
```

</details>

---

### 192.168.178.91 — lta222384.ws.hva.nl

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 445/tcp | microsoft-ds | — | 🔴 CRITICAL | Primary vector for EternalBlue/WannaCry/ransomware |
| 135/tcp | msrpc | Microsoft Windows RPC | 🟠 HIGH | Windows RPC — common attack surface |
| 139/tcp | netbios-ssn | Microsoft Windows netbios-ssn | 🟠 HIGH | Legacy SMB — frequent malware vector |
| 5985/tcp | http | Microsoft HTTPAPI httpd 2.0 | 🟠 HIGH | Windows remote management over HTTP |
| 2701/tcp | cmrcservice | Microsoft Configuration Manager Remote Control service | ⚪ INFO | — |
| 5357/tcp | http | Microsoft HTTPAPI httpd 2.0 | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**http-server-header** op poort 5985:

```
Microsoft-HTTPAPI/2.0
```

**http-csrf** op poort 5985:

```
Couldn't find any CSRF vulnerabilities.
```

**http-dombased-xss** op poort 5985:

```
Couldn't find any DOM based XSS.
```

**http-title** op poort 5985:

```
Not Found
```

**http-stored-xss** op poort 5985:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-dombased-xss** op poort 5357:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 5357:

```
Couldn't find any CSRF vulnerabilities.
```

**http-stored-xss** op poort 5357:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-title** op poort 5357:

```
Service Unavailable
```

**http-server-header** op poort 5357:

```
Microsoft-HTTPAPI/2.0
```

</details>

---

### 192.168.178.135

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 80/tcp | http | OpenWrt uHTTPd | 🔵 LOW | Unencrypted — consider HTTPS redirect |
| 443/tcp | https | — | ⚪ INFO | Check TLS version and certificate validity; nmap script http-vuln-cve2014-3704: see raw output |

<details>
<summary>Script-output</summary>

**http-title** op poort 80:

```
Site doesn't have a title (text/html).
```

**http-csrf** op poort 80:

```
Couldn't find any CSRF vulnerabilities.
```

**http-stored-xss** op poort 80:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-dombased-xss** op poort 80:

```
Couldn't find any DOM based XSS.
```

**ssl-cert** op poort 443:

```
Subject: commonName=tplinkdeco.net/countryName=CN
Not valid before: 2010-01-01T00:00:00
Not valid after:  2030-12-31T00:00:00
```

**ssl-date** op poort 443:

```
TLS randomness does not represent time
```

**http-aspnet-debug** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-vuln-cve2014-3704** op poort 443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-dombased-xss** op poort 443:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 443:

```
Couldn't find any CSRF vulnerabilities.
```

**http-stored-xss** op poort 443:

```
Couldn't find any stored XSS vulnerabilities.
```

</details>

---

### 192.168.178.153

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 8443/tcp | https-alt | — | 🔵 LOW | Check TLS and exposed services |
| 8008/tcp | http | — | ⚪ INFO | — |
| 8009/tcp | ajp13 | — | ⚪ INFO | — |
| 9000/tcp | cslistener | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**ssl-date** op poort 8443:

```
2026-05-29T12:52:19+00:00; -1s from scanner time.
```

**ssl-cert** op poort 8443:

```
Subject: commonName=5602666296008155094/organizationName=Google Inc/stateOrProvinceName=Washington/countryName=US
Not valid before: 2025-07-09T10:14:07
Not valid after:  2045-07-09T10:14:07
```

**http-title** op poort 8443:

```
Site doesn't have a title (text/html).
```

**http-title** op poort 8008:

```
Site doesn't have a title (text/html).
```

**http-dombased-xss** op poort 8008:

```
Couldn't find any DOM based XSS.
```

**http-csrf** op poort 8008:

```
Couldn't find any CSRF vulnerabilities.
```

**http-stored-xss** op poort 8008:

```
Couldn't find any stored XSS vulnerabilities.
```

**ajp-methods** op poort 8009:

```
Failed to get a valid response for the OPTION request
```

**ssl-cert** op poort 8009:

```
Subject: commonName=53442da6-71db-4e0a-8e54-bbd4a9554808
Not valid before: 2026-05-28T13:21:17
Not valid after:  2026-05-30T13:21:17
```

**ssl-date** op poort 8009:

```
TLS randomness does not represent time
```

**ssl-ccs-injection** op poort 9000:

```
No reply from server (TIMEOUT)
```

</details>

---

### 192.168.178.161

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 6668/tcp | irc | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**irc-info** op poort 6668:

```
Unable to open connection
```

</details>

---

### 192.168.178.194

Geen open poorten gevonden.

---

### 192.168.178.196

Geen open poorten gevonden.

---

### 192.168.178.223 — wlan0.home

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 6668/tcp | irc | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**irc-info** op poort 6668:

```
Unable to open connection
```

</details>

---

### 192.168.178.242

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 8443/tcp | https-alt | — | 🔵 LOW | Check TLS and exposed services; nmap script http-vuln-cve2014-3704: see raw output |
| 8008/tcp | http | — | ⚪ INFO | — |
| 8009/tcp | ajp13 | — | ⚪ INFO | — |
| 9000/tcp | cslistener | — | ⚪ INFO | — |
| 10001/tcp | scp-config | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**ssl-ccs-injection** op poort 8443:

```
No reply from server (TIMEOUT)
```

**http-vuln-cve2014-3704** op poort 8443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-aspnet-debug** op poort 8443:

```
ERROR: Script execution failed (use -d to debug)
```

**http-dombased-xss** op poort 8008:

```
Couldn't find any DOM based XSS.
```

**http-title** op poort 8008:

```
Site doesn't have a title (text/html).
```

**http-stored-xss** op poort 8008:

```
Couldn't find any stored XSS vulnerabilities.
```

**http-csrf** op poort 8008:

```
Couldn't find any CSRF vulnerabilities.
```

**ssl-cert** op poort 8009:

```
Subject: commonName=8b33bae8-d3ce-ea6a-d643-d484b820fac5
Not valid before: 2026-05-28T13:29:47
Not valid after:  2026-05-30T13:29:47
```

**ajp-methods** op poort 8009:

```
Failed to get a valid response for the OPTION request
```

**ssl-date** op poort 8009:

```
TLS randomness does not represent time
```

**ssl-ccs-injection** op poort 9000:

```
No reply from server (TIMEOUT)
```

**ssl-ccs-injection** op poort 10001:

```
No reply from server (TIMEOUT)
```

</details>

---

### 192.168.178.243

| Poort | Service | Versie | Ernst | Notities |
|-------|---------|--------|-------|----------|
| 6668/tcp | irc | — | ⚪ INFO | — |

<details>
<summary>Script-output</summary>

**irc-info** op poort 6668:

```
Unable to open connection
```

</details>

---

*Gegenereerd door vuln_scanner.py op 2026-05-29 13:25:54*