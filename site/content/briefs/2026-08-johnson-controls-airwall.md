---
title: Johnson Controls Airwall Hard-coded Credentials and Path Traversal Vulnerabilities
slug: 2026-08-johnson-controls-airwall
description: Johnson Controls Airwall versions 4.0.4 and earlier are affected by CVE-2026-64887 and CVE-2026-34492, allowing attackers to potentially decrypt sensitive data or perform arbitrary file reads.
date: "2026-08-13T16:52:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ics
  - cve-2026-64887
  - cve-2026-34492
vendors:
  - Johnson Controls
products:
  - Airwall
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An attacker with access to application code or binary files can use the hardcoded key to decrypt sensitive application data.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: An attacker can request and obtain the contents of arbitrary files on the server, including sensitive configuration files, source code, credential stores, and private keys.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1005
    technique_name: Data from Local System
    evidence: An attacker can request and obtain the contents of arbitrary files on the server.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-03
  - https://www.cve.org/CVERecord?id=CVE-2026-64887
  - https://www.cve.org/CVERecord?id=CVE-2026-34492
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Airwall firmware to version 4.1.0 or later
      owner: IT Operations
      due: 72h
      evidence: 'Johnson Controls recommends the following defensive measures: Apply v4.1.0 or later patches for all Airwalls.'
  mitigation_plan:
    - priority: immediate
      action: Isolate Airwall management interfaces from the public internet
      owner: IT Operations
      addresses: All affected versions
      evidence: Minimize network exposure for all control system devices and/or systems, ensuring they are not accessible from the internet.
---

Johnson Controls has disclosed two vulnerabilities affecting Airwall products up to and including version 4.0.4. The first, CVE-2026-64887, involves the use of hard-coded cryptographic keys within the application, which are consistent across all installations. This allows an attacker who obtains the key through code analysis or binary inspection to decrypt sensitive application data, configuration files, and database content. The second issue, CVE-2026-34492, is an arbitrary file read vulnerability caused by improper validation of user-supplied input in file system operations. Attackers can leverage path traversal sequences (e.g., ../ or encoded variations) to read sensitive files from the underlying server, including private keys and credential stores. These vulnerabilities pose a significant risk to critical infrastructure sectors, including manufacturing, energy, and transportation, as they could lead to full system compromise if exploited in tandem.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to gain unauthorized access to sensitive system information. By extracting private keys and credentials, an attacker could escalate privileges or pivot into internal networks. Given the deployment of these devices in critical infrastructure sectors, the compromise of Airwall appliances could result in significant operational disruption and data exfiltration.

## Recommendation

- Upgrade all instances of Johnson Controls Airwall to version 4.1.0 or later immediately to patch both CVE-2026-64887 and CVE-2026-34492.
- Audit existing deployments for unauthorized access to configuration files and sensitive key stores.
- Implement network segmentation and strictly restrict management access to these devices, ensuring they are not exposed to the public internet.
- Consult the Johnson Controls Product Security Advisory JCI-PSA-2026-25 and JCI-PSA-2026-18 for detailed hardening steps and remediation guidance.
