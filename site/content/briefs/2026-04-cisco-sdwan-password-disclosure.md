---
title: Cisco Catalyst SD-WAN Manager Password Disclosure Vulnerability (CVE-2026-20128)
slug: 2026-04-cisco-sdwan-password-disclosure
description: Cisco Catalyst SD-WAN Manager stores passwords in a recoverable format, allowing an authenticated local attacker to gain DCA user privileges by accessing a credential file.
date: "2026-04-21T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve-2026-20128
  - credential-access
  - sd-wan
  - cisco
vendors:
  - Cisco
products:
  - Catalyst SD-WAN Manager
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-20128
    cvss: 7.5
    epss: 0.00043
references:
  - https://www.cve.org/CVERecord?id=CVE-2026-20128
  - https://www.cisa.gov/news-events/directives/ed-26-03-mitigate-vulnerabilities-cisco-sd-wan-systems
  - https://www.cisa.gov/news-events/directives/supplemental-direction-ed-26-03-hunt-and-hardening-guidance-cisco-sd-wan-systems
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20128
rules:
  - title: Detect Suspicious SD-WAN Credential File Access
    description: Detects access to sensitive credential files associated with Cisco SD-WAN Manager, indicating potential password disclosure attempts.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - linux
  - title: Detect DCA User Privilege Escalation via CLI
    description: Detects attempts to escalate privileges to the DCA user via command-line interfaces after potentially gaining access to credentials.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Cisco Catalyst SD-WAN Manager is affected by a vulnerability (CVE-2026-20128) that allows for the disclosure of stored passwords. An authenticated, local attacker with low privileges can exploit this vulnerability by accessing a credential file on the filesystem. Successful exploitation grants the attacker DCA user privileges, potentially leading to unauthorized access and control over the SD-WAN environment. CISA has issued Emergency Directive 26-03 and associated guidance to mitigate risks associated with Cisco SD-WAN devices. This vulnerability highlights the importance of proper credential management and access controls in network management systems.

## Attack Chain

1. An attacker gains low-privileged access to the Cisco Catalyst SD-WAN Manager system through legitimate credentials or other vulnerabilities.
2. The attacker navigates the filesystem to locate the DCA user's credential file.
3. The attacker reads the credential file, which contains the DCA user's password in a recoverable format.
4. The attacker decodes or decrypts the password using readily available tools or techniques.
5. The attacker uses the recovered DCA user credentials to authenticate to the SD-WAN Manager with elevated privileges.
6. The attacker leverages the DCA user privileges to perform unauthorized configuration changes or access sensitive data.
7. The attacker potentially pivots to other systems or network segments accessible through the SD-WAN infrastructure.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain complete control over the Cisco Catalyst SD-WAN Manager. This could lead to significant disruption of network services, data breaches, and potential compromise of connected systems. The impact is magnified by the widespread use of SD-WAN in enterprise environments, making this a critical vulnerability for organizations utilizing Cisco Catalyst SD-WAN Manager.

## Recommendation

*   Review and apply the mitigations outlined in CISA's Emergency Directive 26-03 and associated guidance for Cisco SD-WAN devices, as referenced in the overview.
*   Monitor file access events on the Cisco Catalyst SD-WAN Manager system for suspicious access patterns to credential files using the `Detect Suspicious SD-WAN Credential File Access` Sigma rule.
*   Implement stricter access controls and password policies on the Cisco Catalyst SD-WAN Manager to prevent unauthorized access.
*   Apply the security updates provided by Cisco to patch CVE-2026-20128 as they become available.
