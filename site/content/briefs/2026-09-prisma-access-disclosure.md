---
title: Information Disclosure Vulnerability in Prisma Access Agent for Linux
slug: 2026-09-prisma-access-disclosure
description: An information disclosure vulnerability in the Prisma Access Agent for Linux allows local, low-privileged users to access sensitive configuration data and stored credentials (CVE-2026-0305).
date: "2026-09-09T18:58:15Z"
lastmod: "2026-09-09T18:58:30Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - vulnerability
  - information-disclosure
  - linux
  - dlp-bypass
  - endpoint-security
vendors:
  - Palo Alto Networks
products:
  - Prisma Access Agent (< 26.3)
  - Prisma Access Agent (< 26.2 on Windows)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The Prisma Access Agent on Linux enables a local user to access sensitive configuration data and credentials.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: 'Impair Defenses: Disable or Modify Tools'
    evidence: A vulnerability in the EndPoint Data Loss Prevention (DLP) enforcement of Palo Alto Networks Prisma Access Agent enables a local user to bypass configured DLP policy enforcement controls.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0305
  - https://security.paloaltonetworks.com/CVE-2026-0306
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Prisma Access Agent for Linux to version 26.3 or later
      owner: IT Operations
      addresses: CVE-2026-0305
      evidence: Solution section of the vendor advisory recommends upgrading to 26.3 or later.
updates:
  - at: "2026-09-09T18:58:30Z"
    level: L1
    summary: added coverage for Prisma Access Agent (< 26.2 on Windows)
    sources:
      - palo-alto-networks
    source_urls:
      - https://security.paloaltonetworks.com/CVE-2026-0306
---

Palo Alto Networks has disclosed an information disclosure vulnerability, identified as CVE-2026-0305, affecting the Prisma Access Agent on Linux. The vulnerability stems from the improper exposure of sensitive data, allowing a local user with low-level privileges to read sensitive configuration files and credentials managed by the agent. This issue impacts all versions of the Prisma Access Agent on Linux prior to 26.3. Versions on macOS, Windows, iOS, Android, and Chrome OS are not affected by this vulnerability. There are no known workarounds, and organizations running Prisma Access Agent on Linux should prioritize upgrading to version 26.3 or later to remediate the exposure.

## Impact

Successful exploitation of this vulnerability allows a local attacker to access sensitive configuration details and credentials potentially used by the Prisma Access Agent for authentication. This exposure may provide an attacker with the necessary information to pivot within the network or escalate privileges further, depending on the scope of the exposed credentials. There is no evidence of active exploitation in the wild as of the advisory publication date.

## Recommendation

* Upgrade all Prisma Access Agent for Linux installations to version 26.3 or later immediately to address CVE-2026-0305.
* Audit Linux system configurations to ensure that file permissions for configuration directories are restricted to the minimum required users.
* Monitor for suspicious local access patterns or unauthorized attempts to read configuration files located in directories associated with the Prisma Access Agent.
