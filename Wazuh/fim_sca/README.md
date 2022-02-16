## Wazuh FIM (File Integrity Monitoring)

!["Group config"](images/image01.png "Group config")


```xml
<agent_config>
	<!-- Shared agent configuration here -->
	<!-- File integrity monitoring -->
	<syscheck>
		<frequency>60</frequency>
	</syscheck>
	<!-- System inventory -->
	<wodle name="syscollector">
		<interval>10m</interval>
	</wodle>
	<!-- Security Configuration Assessment -->
	<sca>
		<interval>1h</interval>
	</sca>
</agent_config>
```

!["Agent logs"](images/image02.png "Agent logs")


```
2022/02/15 23:00:40 wazuh-agent: INFO: (6010): File integrity monitoring scan frequency: 60 seconds
2022/02/15 23:00:40 wazuh-agent: INFO: (6008): File integrity monitoring scan started.
2022/02/15 23:00:40 rootcheck: INFO: Starting rootcheck scan.
2022/02/15 23:00:43 sca: INFO: Evaluation finished for policy 'C:\Program Files\ossec-agent\ruleset\sca\sca_win_audit.yml'
2022/02/15 23:00:43 sca: INFO: Security Configuration Assessment scan finished. Duration: 3 seconds.
2022/02/15 23:00:47 rootcheck: INFO: Ending rootcheck scan.
2022/02/15 23:00:55 wazuh-agent: INFO: (6009): File integrity monitoring scan ended.
2022/02/15 23:00:55 wazuh-agent: INFO: (6012): Real-time file integrity monitoring started.
2022/02/15 23:01:56 wazuh-agent: INFO: (6008): File integrity monitoring scan started.
2022/02/15 23:02:15 wazuh-agent: INFO: (6009): File integrity monitoring scan ended.
2022/02/15 23:03:16 wazuh-agent: INFO: (6008): File integrity monitoring scan started.
2022/02/15 23:03:34 wazuh-agent: INFO: (6009): File integrity monitoring scan ended.
2022/02/15 23:03:47 wazuh-agent: ERROR: Could not get message for (Application)
2022/02/15 23:03:47 wazuh-agent: ERROR: Could not get message for (Application)
2022/02/15 23:04:35 wazuh-agent: INFO: (6008): File integrity monitoring scan started.
2022/02/15 23:04:53 wazuh-agent: INFO: (6009): File integrity monitoring scan ended.
2022/02/15 23:05:54 wazuh-agent: INFO: (6008): File integrity monitoring scan started.
```

!["Integrity monitoring notifications"](images/image03.png "Integrity monitoring notifications")


```xml
<!-- File integrity monitoring -->
<syscheck>
    ...
    <directories check_all="yes" realtime="yes" report_changes="yes">
        C:\Users\Toni\Documents\m05
    </directories>
    ...
</syscheck>
```

!["Monitored directories"](images/image04.png "Monitored directories")



C:\Windows\win.ini

```
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
[MCI Extensions.BAK]
3g2=MPEGVideo
3gp=MPEGVideo
3gp2=MPEGVideo
3gpp=MPEGVideo
aac=MPEGVideo
adt=MPEGVideo
adts=MPEGVideo
m2t=MPEGVideo
m2ts=MPEGVideo
m2v=MPEGVideo
m4a=MPEGVideo
m4v=MPEGVideo
mod=MPEGVideo
mov=MPEGVideo
mp4=MPEGVideo
mp4v=MPEGVideo
mts=MPEGVideo
ts=MPEGVideo
tts=MPEGVideo
test=Test
```

C:\Windows\System32\drivers\etc\hosts

```
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost
142.250.178.174	toni-pm.herokuapp.com
```

!["Integrity monitoring dashboard"](images/image05.png "Integrity monitoring dashboard")

!["Integrity monitoring alerts"](images/image06.png "Integrity monitoring alerts")

---

## Wazuh SCA (Security Configuration Assessment)

```xml
<sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
</sca>
```

!["SCA Dashboard"](images/image07.png "SCA Dashboard")

!["SCA Inventory"](images/image08.png "SCA Inventory")

---

**14543**	Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'

![](images/image09.png)

![](images/image10.png)

---

**14539**	Ensure Null sessions are not allowed

![](images/image11.png)

![](images/image12.png)

---

**14529**	Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'

![](images/image13.png)

![](images/image32.png)

---

**14528**	Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'


![](images/image15.png)

![](images/image31.png)

---

**14520**	Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'

![](images/image17.png)

![](images/image18.png)

---

**14518**	Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'

![](images/image19.png)

![](images/image20.png)

---

**14517**	Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'

![](images/image21.png)

![](images/image22.png)

---

**14513**	Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'

![](images/image23.png)

![](images/image24.png)

---

**14512**	Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher

![](images/image25.png)

![](images/image26.png)

---

**14509**	Ensure 'Interactive logon: Do not display last user name' is set to 'Enabled'

![](images/image27.png)

![](images/image28.png)

---

**14503**	Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'

![](images/image29.png)

![](images/image30.png)

---

!["SCA Inventory after corrections"](images/image33.png "SCA Inventory after corrections")

!["SCA Dashboard after corrections"](images/image34.png "SCA Dashboard after corrections")