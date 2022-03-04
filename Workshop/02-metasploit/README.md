---
title: "Workshop 2 - Metasploit"
author: "Toni Peraira"
date: "2022-03-04"
version: "1.0"
geometry: left=2.54cm,right=2.54cm,top=2.54cm,bottom=2.54cm
header-right: '\headerlogo'
header-includes:
- '`\newcommand{\headerlogo}{\raisebox{0pt}[0pt]{\includegraphics[width=3cm]{../../institut_montilivi.png}}}`{=latex}'
---

<!--
pandoc README.md -o Toni_Peraira_Workshop_02_Metasploit.pdf --from markdown --template eisvogel --listings --pdf-engine=xelatex
-->

# Workshop 2 - Metasploit

In this workshop we will make a metasploit attack on a Linux machine and get permissions from
root. The victim is a machine extracted from VulnHub (DC-1) that has a Wazuh agent installed and
is sending events and alerts to our Wazuh manager. After the attack, we need to make one
report of events & alerts collected in Wazuh.

```
Wazuh agent to attack
IP: 192.168.128.48
```

```
Wazuh Manager
IP: 192.168.128.80
```

* Investigate which ports the victim has open:

nmap -sV 192.168.128.48

* What web content do you have?

* Run *msfconsole* and see if Metasploit has any *exploit* for this content:

*search drupal*

* One that you can use is the *Drupal Drupalgeddon 2 Forms API Property Injection* that
exploits the [https://nvd.nist.gov/vuln/detail/CVE-2018-7600](CVE-2018-7600) vulnerability.

* Get machine information:
    - sysinfo
    - getuid
    - whoami

* At this point, the exploit works and you are inside the victim with the user *www-data*. Now
you need to escalate privileges, so you have to open a *reverse shell* and with Python generate one
terminal tty:

Now we will search for files with SUID permissions, those with the 's' bit enabled. This property is necessary for normal users to perform tasks that
require higher privileges

In this case, we will use the last of all these files:

Now, with the *whoami* command, check which user you are and you will see that you already have permissions of administrator.