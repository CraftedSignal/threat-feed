---
title: Cisco 802.1X (dot1x) Disabled on Network Interface
slug: 2024-01-cisco-dot1x-disabled
description: Detection of manual disablement of IEEE 802.1X (dot1x) on a Cisco network device interface, potentially allowing unauthorized network access and lateral movement.
date: "2024-01-03T18:23:00Z"
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

The disabling of 802.1X authentication on a Cisco network device can bypass Network Access Control (NAC) mechanisms, potentially granting unauthorized devices access to the internal network. Attackers or malicious insiders might disable dot1x to establish persistence or facilitate lateral movement by connecting rogue devices to the network. This can be accomplished through CLI commands such as 'access-session port-control force-authorized' or 'no dot1x system-auth-control', depending on the IOS…
