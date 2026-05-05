---
title: Johnson Controls CEM AC2000 Privilege Escalation via DLL Hijacking
slug: 2026-05-johnson-controls-privesc
description: A vulnerability exists in Johnson Controls CEM AC2000 versions 12.0, 11.0, and 10.6 due to an uncontrolled search path element that could allow a standard user to escalate privileges on the host machine via DLL hijacking.
date: "2026-05-05T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - dll-hijacking
  - cem-ac2000
vendors:
  - Johnson Controls Inc.
products:
  - CEM AC2000
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-125-05
  - https://www.cve.org/CVERecord?id=CVE-2026-21661
  - https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories
rules:
  - title: Suspicious DLL Load by CEM AC2000
    description: Detects suspicious DLL loading by CEM AC2000 from unusual paths, indicative of DLL hijacking.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - image_load
      - windows
  - title: Potential Privilege Escalation via Malicious DLL in User Profile
    description: Detects the creation of DLL files in user profile directories, which might be exploited for DLL hijacking.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Johnson Controls CEM AC2000, a physical access control system, is vulnerable to DLL hijacking due to an uncontrolled search path element. This vulnerability, identified as CVE-2026-21661, affects versions 12.0, 11.0, and 10.6. Successful exploitation could allow a standard user to escalate their privileges on the host machine. The affected sectors include Critical Manufacturing, Commercial Facilities, Government Services and Facilities, Transportation Systems, and Energy. Johnson Controls recommends upgrading to specific releases to mitigate this vulnerability. This privilege escalation could grant unauthorized access to sensitive areas and systems controlled by the CEM AC2000 software.

## Attack Chain

1. A standard user logs into a Windows system where a vulnerable version of Johnson Controls CEM AC2000 is installed.
2. The user executes the CEM AC2000 application, which attempts to load a specific DLL file.
3. Due to an uncontrolled search path element (CWE-427), the application searches for the DLL in a predictable, user-writable directory before searching the system's legitimate DLL directories.
4. The attacker places a malicious DLL file with the expected name in the user-writable directory.
5. The CEM AC2000 application loads the malicious DLL instead of the legitimate one.
6. The malicious DLL executes with the privileges of the CEM AC2000 application, which, due to the vulnerability, are elevated compared to the initial user.
7. The attacker now has elevated privileges on the host machine, potentially allowing them to access sensitive data or control system functions.
8. The attacker can now install malicious software, modify system settings, or exfiltrate data.

## Impact

Successful exploitation of CVE-2026-21661 allows a standard user to escalate privileges on the host machine running Johnson Controls CEM AC2000. This can lead to unauthorized access to sensitive areas controlled by the system, manipulation of physical security controls, or further compromise of the underlying operating system. Given the wide deployment of CEM AC2000 across critical infrastructure sectors, this vulnerability poses a significant risk to physical and cyber security.

## Recommendation

*   Upgrade CEM AC 2000 12.0 to 12.0 Release 10 as recommended by Johnson Controls to remediate CVE-2026-21661.
*   Upgrade CEM AC 2000 11.0 to 11.0 Release 9 as recommended by Johnson Controls to remediate CVE-2026-21661.
*   Upgrade CEM AC 2000 10.6 to 10.6 Release 3 as recommended by Johnson Controls to remediate CVE-2026-21661.
*   Monitor process creation events for CEM AC2000 loading DLLs from unusual or user-writable paths using the "Suspicious DLL Load by CEM AC2000" Sigma rule.
