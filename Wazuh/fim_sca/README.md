## Wazuh FIM (File Integrity Monitoring)

This module runs periodic scans of the agent system, this action stores the checksums and atributes of the monitored elements and Windows registry in a local database.

In the next scan will comare the current checksums with the stored values. 


When a change is detected, it is reported in our Wazuh manager.

Therefore, it is the appropriate module to identify possible intrusions that may have altered the integrity of our system.

!["Group config"](images/image01.png "Group config")

We change the file integrity monitoring frequency to make our tests. We set the frequency in 60 seconds.

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
In the agent logs we can see how the integrity check has been done every 60 seconds.

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

We can see the events in our Wazuh agent Integrity Monitoring  dashboard.

!["Integrity monitoring notifications"](images/image03.png "Integrity monitoring notifications")

We can also check the integrity of a directory that we choose, changing the agent or group config. In our case we are going to check the integrity of the directory *C:\Users\Toni\Documents\m05*

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

The custom directory is added in the monitored directories section.

!["Monitored directories"](images/image04.png "Monitored directories")

Let's check how well the integrity monitoring works. We will edit some files and directories that we know are included in the process.

- C:\Windows\win.ini

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

- C:\Windows\System32\drivers\etc\hosts

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

- Added C:\Windows\System32\drivers\etc\exploit

- Added C:\Users\Toni\Documents\m05\m05_exploit

These changes have generated alerts in the Integrity monitoring dashboard of the agent.

!["Integrity monitoring dashboard"](images/image05.png "Integrity monitoring dashboard")

!["Integrity monitoring alerts"](images/image06.png "Integrity monitoring alerts")

---

## Wazuh SCA (Security Configuration Assessment)

This module aims to provide the user with the best possible experience when performing scans about hardening and configuration policies.

This allows us to improve some security elements of the system

The first thing is always to activate the functionality in the agent config.

```xml
<sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
</sca>
```

Once configured, we can refresh the SCA dashboard.

This action will provide us with information about those points that we can improve in the agent

!["SCA Dashboard"](images/image07.png "SCA Dashboard")

!["SCA Inventory"](images/image08.png "SCA Inventory")

I attach the failed points of my agent and how I have solved it based on the information received.

In total there are 11 points to correct.

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

Once all the points have been corrected, we have the agent a little safer.

!["SCA Inventory after corrections"](images/image33.png "SCA Inventory after corrections")

!["SCA Dashboard after corrections"](images/image34.png "SCA Dashboard after corrections")