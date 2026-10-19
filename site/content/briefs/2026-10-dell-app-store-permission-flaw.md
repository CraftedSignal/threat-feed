---
title: Dell Application Store Incorrect Permission Assignment Vulnerability
slug: 2026-10-dell-app-store-permission-flaw
description: An incorrect permission assignment vulnerability in the Dell Application Store allows a local low-privileged attacker to disclose sensitive information.
date: "2026-10-19T22:24:12Z"
lastmod: "2026-10-19T22:24:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dell:application_store:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - local-access
  - information-disclosure
vendors:
  - Dell
products:
  - Application Store (< 26.05.0.7)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A low privileged attacker with local access could potentially exploit this vulnerability, leading to Disclosure of sensitive information
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: A low privileged attacker with local access could potentially exploit this vulnerability, leading to an Elevation of Privilege and arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-71169
    cvss: 7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71169
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71170
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Dell Application Store to 26.05.0.7
      owner: IT Operations
      due: 72h
      evidence: Vulnerability disclosure regarding CVE-2026-71169
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 26.05.0.7 or later
      owner: IT Operations
      addresses: CVE-2026-71169
      evidence: NVD source advisory
updates:
  - at: "2026-10-19T22:24:18Z"
    level: L2
    summary: added coverage for Application Store (< 26.05.0.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71170
---

Dell Application Store versions prior to 26.05.0.7 contain an incorrect permission assignment vulnerability categorized as a critical resource access issue. This flaw resides within the application’s local handling of resource permissions. A local attacker possessing low-level system privileges can exploit this vulnerability to bypass intended access controls, resulting in the disclosure of sensitive information stored by or accessible to the application. Given that the Dell Application Store is a component integrated into various Dell systems, this flaw poses a risk to internal environments where local user access is shared or where non-administrative users are granted interactive login rights. Defenders should prioritize updating the Dell Application Store to version 26.05.0.7 or later to mitigate unauthorized access to local sensitive data.

## Impact

Successful exploitation allows local, low-privileged users to read sensitive information that should be restricted, potentially leading to the compromise of credentials, configuration data, or private user information contained within the application's environment.

## Recommendation

- Upgrade the Dell Application Store to version 26.05.0.7 or later across all managed endpoints to resolve CVE-2026-71169.
- Audit local file system permissions for directories associated with the Dell Application Store to ensure non-privileged users cannot access sensitive configuration files.
- Monitor for unauthorized access attempts to local application data stores by low-privileged user accounts.
