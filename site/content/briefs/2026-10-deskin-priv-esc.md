---
title: Local Privilege Escalation in Deskin macOS Installer Service
slug: 2026-10-deskin-priv-esc
description: Deskin versions through 3.3.4.3 contain an authentication vulnerability in the com.deskin.service.installer XPC service that allows local attackers to execute arbitrary installer packages as root.
date: "2026-10-08T22:15:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:deskin:deskin:*:*:*:*:*:*:*:*
vendors:
  - Deskin
products:
  - Deskin (<= 3.3.4.3)
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An unprivileged local attacker can connect to the root-owned service and invoke the installer method to execute arbitrary installer packages with root privileges.
    confidence_band: high
cves:
  - id: CVE-2026-11318
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-11318
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review local macOS endpoints for the presence of Deskin version 3.3.4.3 or earlier.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-11318 indicates this version range is vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Deskin to the latest available version beyond 3.3.4.3 to remediate CVE-2026-11318.
      owner: IT Operations
      addresses: CVE-2026-11318
      evidence: NVD vulnerability disclosure for CVE-2026-11318.
---

Deskin versions 3.3.4.3 and earlier contain a critical local privilege escalation vulnerability within the 'com.deskin.service.installer' XPC service on macOS. The XPC service fails to properly authenticate requests, allowing unprivileged local users to interact with the service directly. An attacker can leverage this misconfiguration to invoke the privileged installer method, which executes installer packages with root-level permissions. Because the service is owned by the root user and performs no credential validation, an attacker can supply a malicious installer package to gain full system control. This vulnerability poses a significant risk to macOS environments where Deskin is installed, as it allows standard users to bypass system security restrictions and escalate to root privileges without requiring existing administrative access.

## Impact

Successful exploitation of CVE-2026-11318 results in a full root compromise of the affected macOS host. This allows attackers to install persistent backdoors, access sensitive data across the file system, and disable security controls. This vulnerability affects all Deskin deployments through version 3.3.4.3.

## Recommendation

- Monitor for unauthorized execution of installer processes originating from the Deskin service.
- Review internal software update policies for Deskin and ensure systems are transitioned to a version beyond 3.3.4.3 once a patch is confirmed available by the vendor.
- Audit local user activity on macOS endpoints for suspicious calls to XPC services identified as root-owned.
