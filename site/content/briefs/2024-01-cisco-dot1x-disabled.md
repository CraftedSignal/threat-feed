---
title: Cisco 802.1X (dot1x) Disabled on Network Interface
slug: 2024-01-cisco-dot1x-disabled
description: Detection of manual disablement of IEEE 802.1X (dot1x) on a Cisco network device interface, potentially allowing unauthorized network access and lateral movement.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - attack.defense-evasion
  - attack.persistence
  - attack.credential-access
  - attack.t1562.001
  - attack.t1556.004
vendors:
  - Cisco
products:
  - IOS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1556
    technique_name: Modify Authentication Process
references:
  - https://www.cisco.com/en/US/docs/ios-xml/ios/san/command/san-xe-3se-3850-cr-book_chapter_00.html#wp3394428680
  - https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/a1/sec-a1-xe-3se-3850-cr-book/sec-a1-xe-3se-3850-cr-book_chapter_010.html#wp3502072400
  - https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst2960/software/release/12-2_53_se/command/reference/2960ComRef/cli1.html#47220
rules:
  - title: Cisco Dot1x Disabled - Specific Interface
    description: Detects the disabling of 802.1X authentication on a specific Cisco network device interface.
    platform: sigma
    severity: medium
    tactics:
      - credential-access
      - defense-evasion
      - persistence
    techniques:
      - T1556.004
      - T1562.001
    data_sources:
      - aaa
      - cisco
  - title: Cisco Dot1x Disabled - Global
    description: Detects the global disabling of 802.1X authentication on a Cisco network device.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - defense-evasion
      - persistence
    techniques:
      - T1556.004
      - T1562.001
    data_sources:
      - aaa
      - cisco
rules_count: 2
---

The disabling of 802.1X authentication on a Cisco network device can bypass Network Access Control (NAC) mechanisms, potentially granting unauthorized devices access to the internal network. Attackers or malicious insiders might disable dot1x to establish persistence or facilitate lateral movement by connecting rogue devices to the network. This can be accomplished through CLI commands such as 'access-session port-control force-authorized' or 'no dot1x system-auth-control', depending on the IOS version. These commands either disable 802.1X on a specific interface or globally across the device. The targeted scope is Cisco network devices utilizing 802.1X for network access control.

## Attack Chain

1.  Attacker gains privileged access to a Cisco network device via compromised credentials or exploiting a vulnerability.
2.  Attacker executes CLI commands to disable 802.1X authentication on a specific interface or globally.
3.  Commands used may include 'access-session port-control force-authorized', 'authentication port-control force-authorized', 'dot1x port-control force-authorized', 'no access-session port-control', 'no authentication port-control', 'no dot1x port-control', or 'no dot1x system-auth-control'.
4.  The network interface transitions to a force-authorized state, bypassing the normal authentication process.
5.  An unauthorized device is connected to the compromised network interface.
6.  The unauthorized device gains network access without proper authentication or authorization.
7.  The attacker leverages the unauthorized access for lateral movement to other systems on the network.
8.  The attacker exfiltrates sensitive data or deploys malicious payloads across the network.

## Impact

Successful disabling of dot1x can lead to unauthorized network access, allowing attackers to bypass security controls. This can result in the compromise of sensitive data, the spread of malware, and the disruption of network services. The number of affected devices and the scope of the compromise depend on the network architecture and the attacker's objectives. The impact could range from a single compromised workstation to a full-scale network breach affecting thousands of devices and users.

## Recommendation

*   Deploy the Sigma rule `Cisco Dot1x Disabled` to your SIEM to detect the execution of commands that disable 802.1X authentication.
*   Monitor Cisco AAA logs for events containing keywords such as 'access-session port-control force-authorized' and 'no dot1x system-auth-control' to identify potential attempts to disable dot1x.
*   Implement multi-factor authentication (MFA) for all administrative access to Cisco network devices to prevent unauthorized command execution.
*   Regularly review and audit the configuration of Cisco network devices to ensure that 802.1X is enabled and properly configured on all relevant interfaces.
