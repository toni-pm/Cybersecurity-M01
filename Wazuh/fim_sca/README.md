
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

```xml
<sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
</sca>
```



14543
Ensure 'MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)' is set to 'Disabled'
Registry: HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
Failed

**Rationale**

If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks that the computer is connected to. Also, if you enable automatic logon, the password is stored in the registry in plaintext. The specific registry key that stores this setting is remotely readable by the Authenticated Users group. As a result, this entry is appropriate only if the computer is physically secured and if you ensure that untrusted users cannot remotely see the registry.

**Remediation**

To establish the recommended configuration via GP, set the following UI path to Disabled: Computer Configuration\Policies\Administrative Templates\MSS (Legacy)\MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended) Note: This Group Policy path does not exist by default. An additional Group Policy template (MSS-legacy.admx/adml) is required - it is available from this TechNet blog post: The MSS settings - Microsoft Security Guidance blog.

**Description**

This setting is separate from the Welcome screen feature in Windows XP and Windows Vista; if that feature is disabled, this setting is not disabled. If you configure a computer for automatic logon, anyone who can physically gain access to the computer can also gain access to everything that is on the computer, including any network or networks to which the computer is connected. Also, if you enable automatic logon, the password is stored in the registry in plaintext, and the specific registry key that stores this value is remotely readable by the Authenticated Users group. The recommended state for this setting is: Disabled.

**Check (Condition: all)**

r:HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon -> AutoAdminLogon -> 0

**Compliance**

cis_csc: 16

---

14539
Ensure Null sessions are not allowed
Registry: HKLM\System\CurrentControlSet\Control\Lsa
Failed

**Check (Condition: all)**
r:HKLM\System\CurrentControlSet\Control\Lsa -> RestrictAnonymous -> 1

Compliance
nist_800_53: SI.4

pci_dss: 11.4

tsc: CC6.1,CC6.8,CC7.2,CC7.3,CC7.4

---

14529
Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'
Registry: HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0
Failed

Rationale
You can enable all of the options for this policy setting to help protect network traffic that uses the NTLM Security Support Provider (NTLM SSP) from being exposed or tampered with by an attacker who has gained access to the same network. That is, these options help protect against man-in-the-middle attacks.
Remediation
To establish the recommended configuration via GP, set the following UI path to Require NTLMv2 session security, Require 128-bit encryption: Computer Configuration\Policies\Windows Settings\Security Settings\Local Policies\Security Options\Network security: Minimum session security for NTLM SSP based (including secure RPC) servers.
Description
This policy setting determines which behaviors are allowed by servers for applications using the NTLM Security Support Provider (SSP). The SSP Interface (SSPI) is used by applications that need authentication services. The setting does not modify how the authentication sequence works but instead require certain behaviors in applications that use the SSPI. The recommended state for this setting is: Require NTLMv2 session security, Require 128-bit encryption. Note: These values are dependent on the Network security.
Check (Condition: all)
r:HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\MSV1_0 -> NTLMMinServerSec -> 537395200
Compliance
cis_csc: 13
