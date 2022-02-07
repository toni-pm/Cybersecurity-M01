# WAZUH

Installation.

Server machine:

> Linux Mint 20 Ulyana

```console
curl -so ~/unattended-installation.sh https://packages.wazuh.com/resources/4.2/open-distro/unattended-installation/unattended-installation.sh && bash ~/unattended-installation.sh -o
```

```
The password for wazuh is m0QrN1jq-s8gMjzMJc6g3Ie58DukpJQO

The password for admin is 3Tg1fwbCXrNAGninRYAqP7ukZ8EpBILT

The password for kibanaserver is x_OJ-yOTFDmhhKuIkd--ZFEYrBEEH9Ja

The password for kibanaro is ZOhTL4vD55wyO9Ck7ULp5USX_xhDrseJ

The password for logstash is yauguYHrlhV02W7wRT0EzZxKEqeljOU0

The password for readall is T7_etdK5qYhqSZ0UqbuvxATkPcl-zAnU

The password for snapshotrestore is HQo2fJcz4O5_xj_fUg7_B2Rc--F4QU7e

The password for wazuh_admin is p-uRIpsD-FIb-VSIgCpMB80vmNyHJ96C

The password for wazuh_user is D-9frD1-8LpVd_iCgxvYKzvHuVaf1asn
```

Agent machine:

```console
WAZUH_MANAGER="192.168.128.87" apt-get install wazuh-agent
```

Agent machine:

```console
➜  ~ WAZUH_MANAGER="192.168.128.87" apt-get install wazuh-agent
```

```
➜  ~ sudo vim /var/ossec/etc/ossec.conf
<!-- Added directives to pick up system vulnerabilities -->
    <wodle name="syscollector">
        <disabled>no</disabled>
        <interval>1h</interval>
        <os>yes</os>
        <packages>yes</packages>
        <hotfixes>yes</hotfixes>
    </wodle>
<!-- End of added directives -->
```

```
➜  ~ sudo vim /var/ossec/etc/ossec.conf
  <!-- System inventory -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>

    <!-- Database synchronization settings -->
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>
```

Server machine:

```
➜  ~ sudo vim /var/ossec/etc/ossec.conf
```

```
  <vulnerability-detector>
    <enabled>yes</enabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>

    <!-- Ubuntu OS vulnerabilities --> 
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <update_interval>1h</update_interval>
    </provider>

    <!-- Debian OS vulnerabilities -->  
    <provider name="debian">
      <enabled>no</enabled>
      <os>stretch</os>
      <os>buster</os>
      <update_interval>1h</update_interval>
    </provider>

    <!-- RedHat OS vulnerabilities -->  
    <provider name="redhat">
      <enabled>no</enabled>
      <os>5</os>
      <os>6</os>
      <os>7</os>
      <os>8</os>
      <update_interval>1h</update_interval>
    </provider>

    <!-- Windows OS vulnerabilities -->
    <provider name="msu">
      <enabled>yes</enabled>
      <update_interval>1h</update_interval>
    </provider>

    <!-- Aggregate vulnerabilities -->
    <provider name="nvd">
      <enabled>yes</enabled>
      <update_from_year>2010</update_from_year>
      <update_interval>1h</update_interval>
    </provider>

  </vulnerability-detector>
```

```
➜  ~ sudo systemctl restart wazuh-manager
```

```
"Rule ID",Description,Count
23506,"CVE-2016-1585 affects apparmor",1
23506,"CVE-2016-1585 affects libapparmor1",1
23506,"CVE-2021-29921 affects libpython3.8",1
23506,"CVE-2021-29921 affects libpython3.8-minimal",1
23506,"CVE-2021-29921 affects libpython3.8-stdlib",1
23506,"CVE-2021-29921 affects python3.8",1
23506,"CVE-2021-29921 affects python3.8-minimal",1
23506,"CVE-2021-30498 affects libcaca0",1
23506,"CVE-2021-30499 affects libcaca0",1
23506,"CVE-2021-31870 affects klibc-utils",1
23506,"CVE-2021-31870 affects libklibc",1
23506,"CVE-2021-31873 affects klibc-utils",1
23506,"CVE-2021-31873 affects libklibc",1
23506,"CVE-2021-32810 affects firefox",1
23506,"CVE-2021-34552 affects python3-pil",1
23506,"CVE-2021-35942 affects libc-bin",1
23506,"CVE-2021-35942 affects libc6",1
23506,"CVE-2021-35942 affects locales",1
23506,"CVE-2021-3711 affects libssl1.1",1
23506,"CVE-2021-3711 affects openssl",1
```



```
kali@kali:~$ sudo apt autoremove -y
kali@kali:~$ sudo apt-get update -y -y
kali@kali:~$ sudo apt-get upgrade -y
```

[CVE-2016-1585](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1585)

In all versions of AppArmor mount rules are accidentally widened when compiled.

```
There is no fix.
```

[CVE-2021-29921](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29921)

In Python before 3,9,5, the ipaddress library mishandles leading zero characters in the octets of an IP address string. This (in some situations) allows attackers to bypass access control that is based on IP addresses.

```
kali@kali:~$ python3 --version
Python 3.8.10
kali@kali:~$ sudo add-apt-repository ppa:deadsnakes/ppa
kali@kali:~$ sudo apt update
kali@kali:~$ sudo apt install -y python3.10
kali@kali:~$ sudo update-alternatives --set python3 /usr/bin/python3.10
kali@kali:~$ python3 --version
Python 3.10.2
kali@kali:~$ sudo apt-get remove  python3-apt
kali@kali:~$ sudo apt-get install python3-apt
kali@kali:~$ sudo apt-get install --reinstall python3-apt
```

[CVE-2021-30498](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30498)

A flaw was found in libcaca. A heap buffer overflow in export.c in function export_tga might lead to memory corruption and other potential consequences.

Fixed in https://github.com/cacalabs/libcaca/commit/ab04483ee1a846d6b74b2e6248e980152baec3f6.

```
kali@kali:/opt$ sudo wget http://ftp.gnu.org/gnu/autoconf/autoconf-latest.tar.gz --no-check-certificate
kali@kali:/opt$ sudo tar -xzvf autoconf-latest.tar.gz 
kali@kali:/opt$ cd autoconf-2.71/
kali@kali:/opt/autoconf-2.71$ sudo ./configure 
kali@kali:/opt/autoconf-2.71$ sudo make
kali@kali:/opt/autoconf-2.71$ sudo make install

```

```
kali@kali:/opt$ sudo wget https://github.com/cacalabs/libcaca/archive/refs/heads/main.zip --no-check-certificate
kali@kali:/opt$ sudo unzip main.zip 
kali@kali:/opt/libcaca-main$ sudo apt-get install libtool
kali@kali:/opt/libcaca-main$ sudo ./bootstrap 
kali@kali:/opt/libcaca-main$ sudo ./configure 
kali@kali:/opt/libcaca-main$ sudo make
kali@kali:/opt/libcaca-main$ sudo make install

```

[CVE-2021-30499](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30499)

A flaw was found in libcaca. A buffer overflow of export.c in function export_troff might lead to memory corruption and other potential consequences.

Fixed in https://github.com/cacalabs/libcaca/commit/ab04483ee1a846d6b74b2e6248e980152baec3f6.

[CVE-2021-31870](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31870)

An issue was discovered in klibc before 2.0.9. Multiplication in the calloc() function may result in an integer overflow and a subsequent heap buffer overflow.

```
kali@kali:~$ sudo apt upgrade -y klibc-utils
```

[CVE-2021-31873](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-31873)

An issue was discovered in klibc before 2.0.9. Additions in the malloc() function may result in an integer overflow and a subsequent heap buffer overflow.

```
kali@kali:~$ sudo apt upgrade -y klibc-utils
```

[CVE-2021-32810](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-32810)

crossbeam-deque is a package of work-stealing deques for building task schedulers when programming in Rust. In versions prior to 0.7.4 and 0.8.0, the result of the race condition is that one or more tasks in the worker queue can be popped twice instead of other tasks that are forgotten and never popped. If tasks are allocated on the heap, this can cause double free and a memory leak. If not, this still can cause a logical bug. Crates using `Stealer::steal`, `Stealer::steal_batch`, or `Stealer::steal_batch_and_pop` are affected by this issue. This has been fixed in crossbeam-deque 0.8.1 and 0.7.4.

[CVE-2021-34552](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-34552)

Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7 allow an attacker to pass controlled parameters directly into a convert function to trigger a buffer overflow in Convert.c.

[CVE-2021-35942](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35942)

The wordexp function in the GNU C Library (aka glibc) through 2.33 may crash or read arbitrary memory in parse_param (in posix/wordexp.c) when called with an untrusted, crafted pattern, potentially resulting in a denial of service or disclosure of information. This occurs because atoi was used but strtoul should have been used to ensure correct calculations.

```
kali@kali:~$ ldd --version
ldd (Ubuntu GLIBC 2.31-0ubuntu9.2) 2.31
Copyright (C) 2020 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
Written by Roland McGrath and Ulrich Drepper.
kali@kali:~$ cd /opt
kali@kali:/opt$ sudo wget https://ftp.gnu.org/gnu/glibc/glibc-2.35.tar.gz --no-check-certificate
kali@kali:/opt$ sudo tar -xzvf glibc-2.35.tar.gz 
kali@kali:/opt$ sudo mkdir -p glibc-2.35/build
kali@kali:/opt$ cd glibc-2.35/build/
kali@kali:/opt/glibc-2.35/build$ sudo apt install -y bison
kali@kali:/opt/glibc-2.35/build$ sudo apt install -y gawk
kali@kali:/opt/glibc-2.35/build$ sudo ../configure --prefix=/opt/glibc-2.35
kali@kali:/opt/glibc-2.35/build$ sudo make
kali@kali:/opt/glibc-2.35/build$ sudo make test
kali@kali:/opt/glibc-2.35/build$ sudo make install

```

[CVE-2021-3711](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3711)

In order to decrypt SM2 encrypted data an application is expected to call the API function EVP_PKEY_decrypt(). Typically an application will call this function twice. The first time, on entry, the "out" parameter can be NULL and, on exit, the "outlen" parameter is populated with the buffer size required to hold the decrypted plaintext. The application can then allocate a sufficiently sized buffer and call EVP_PKEY_decrypt() again, but this time passing a non-NULL value for the "out" parameter. A bug in the implementation of the SM2 decryption code means that the calculation of the buffer size required to hold the plaintext returned by the first call to EVP_PKEY_decrypt() can be smaller than the actual size required by the second call. This can lead to a buffer overflow when EVP_PKEY_decrypt() is called by the application a second time with a buffer that is too small. A malicious attacker who is able present SM2 content for decryption to an application could cause attacker chosen data to overflow the buffer by up to a maximum of 62 bytes altering the contents of other data held after the buffer, possibly changing application behaviour or causing the application to crash. The location of the buffer is application dependent but is typically heap allocated. Fixed in OpenSSL 1.1.1l (Affected 1.1.1-1.1.1k).

```
kali@kali:/opt$ openssl version
OpenSSL 1.1.1f  31 Mar 2020

kali@kali:/opt$ sudo mv /usr/bin/openssl /usr/bin/openssl.old #backup old openssl
kali@kali:/opt$ sudo wget https://www.openssl.org/source/openssl-1.1.1m.tar.gz --no-check-certificate
kali@kali:/opt$ sudo tar -xf openssl-1.1.1m.tar.gz
kali@kali:/opt$ cd openssl-1.1.1m/

kali@kali:/opt/openssl-1.1.1m$ sudo ./config
Operating system: x86_64-whatever-linux2
Configuring OpenSSL version 1.1.1m (0x101010dfL) for linux-x86_64
Using os-specific seed configuration
Creating configdata.pm
Creating Makefile

**********************************************************************
***                                                                ***
***   OpenSSL has been successfully configured                     ***
***                                                                ***
***   If you encounter a problem while building, please open an    ***
***   issue on GitHub <https://github.com/openssl/openssl/issues>  ***
***   and include the output from the following command:           ***
***                                                                ***
***       perl configdata.pm --dump                                ***
***                                                                ***
***   (If you are new to OpenSSL, you might want to consult the    ***
***   'Troubleshooting' section in the INSTALL file first)         ***
***                                                                ***
**********************************************************************
kali@kali:/opt/openssl-1.1.1m$ sudo apt-get install -y build-essential
kali@kali:/opt/openssl-1.1.1m$ sudo apt-get install -y libz-dev
kali@kali:/opt/openssl-1.1.1m$ sudo make
kali@kali:/opt/openssl-1.1.1m$ sudo make test
kali@kali:/opt/openssl-1.1.1m$ sudo make install
kali@kali:/opt/openssl-1.1.1m$ which openssl
/usr/bin/openssl
kali@kali:~/openssl-1.1.1m$ sudo mv ~/openssl-1.1.1m /opt/openssl-1.1.1m
kali@kali:~/openssl-1.1.1m$ sudo ln -s /usr/local/bin/openssl /usr/bin/openssl
kali@kali:/opt/openssl-1.1.1m$ sudo ldconfig
kali@kali:/opt/openssl-1.1.1m$ openssl version
OpenSSL 1.1.1m  14 Dec 2021
```
