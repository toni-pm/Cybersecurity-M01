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