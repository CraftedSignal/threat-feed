---
title: Privilege Escalation Vulnerability in Lenovo Dock Manager
slug: 2026-08-lenovo-dock-manager-lpe
description: Lenovo Dock Manager versions prior to 1.6.5.3 contain a local privilege escalation vulnerability due to an improperly protected key, allowing authenticated local users to gain elevated access.
date: "2026-08-13T15:38:48Z"
lastmod: "2026-08-13T15:38:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - lenovo
vendors:
  - Lenovo
products:
  - Dock Manager
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An improperly protected key was discovered in Lenovo Dock Manager that could allow a local authenticated user to escalate privileges.
    confidence_band: high
cves:
  - id: CVE-2026-63424
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63424
  - https://support.lenovo.com/us/en/product_security/LEN-223470
  - https://nvd.nist.gov/vuln/detail/CVE-2026-63425
  - https://support.lenovo.com/us/en/solutions/ht037099#dm
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update Lenovo Dock Manager to 1.6.5.3 or later
      owner: IT Operations
      due: 72h
      evidence: Lenovo Security Advisory LEN-223470
updates:
  - at: "2026-08-13T15:38:58Z"
    level: L2
    summary: added coverage for Dock Manager
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-63425
---

Lenovo has identified a security vulnerability in Lenovo Dock Manager (CVE-2026-63424) that allows a local authenticated user to escalate privileges. The vulnerability, classified as CWE-261 (Weak Encoding for Password), exists due to an improperly protected key used by the application. This issue impacts all versions of Lenovo Dock Manager prior to 1.6.5.3. By exploiting this weak protection, an attacker with local, authenticated access to the machine could potentially manipulate the application's configuration or authentication mechanism to achieve higher privileges on the host system.

## Impact

Successful exploitation could allow an attacker to escalate privileges to the level of the user running the Lenovo Dock Manager service, which typically runs with elevated permissions in a Windows environment. This can lead to full system compromise if the service is running as SYSTEM. The vulnerability specifically affects enterprise environments where Dock Manager is deployed to manage firmware and configuration for Lenovo docking stations.

## Recommendation

Prioritize the update of Lenovo Dock Manager to version 1.6.5.3 or later across all managed endpoints. Review the Lenovo Security Advisory LEN-223470 for specific deployment guidance and patch verification procedures.
