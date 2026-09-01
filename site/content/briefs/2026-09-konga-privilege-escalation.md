---
title: Privilege Escalation in Konga via Insecure Library Loading
slug: 2026-09-konga-privilege-escalation
description: Konga versions before 2.1.0 are vulnerable to privilege escalation on Windows via an insecure library loading path that allows low-privileged local users to execute arbitrary code.
date: "2026-09-01T21:08:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:konga:konga:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - windows
vendors:
  - Konga
products:
  - Konga (< 2.1.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: An attacker can exploit this by creating a missing directory in a location writable by any authenticated user and placing a malicious OpenSSL configuration or library file within it.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: When the application launches, it loads the malicious file with the privileges of the executing account, enabling arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-45221
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45221
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Konga to version 2.1.0 or later on all Windows hosts.
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies version 2.1.0 as the remediation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Konga to 2.1.0 or later.
      owner: IT Operations
      addresses: CVE-2026-45221
      evidence: NVD vulnerability disclosure.
---

Konga versions prior to 2.1.0 are susceptible to a privilege escalation vulnerability on Windows systems. The application attempts to load OpenSSL configuration or library files from a specific filesystem path that is absent by default in standard installations. Because this target directory resides in a location writable by any authenticated local user, a malicious actor can pre-create the directory and place crafted OpenSSL configuration or library files within it. When the Konga application or associated service is executed, it prioritizes loading these attacker-controlled files from the planted path. This results in the execution of arbitrary code with the privileges of the user or service account running the application, potentially leading to full system compromise if the service operates with elevated permissions.

## Impact

Successful exploitation allows a local attacker with low-privileged access to escalate their permissions to the level of the Konga application process. In environments where Konga services run as elevated service accounts, this can lead to full administrative control over the host system. This vulnerability affects all Konga deployments on Windows platforms prior to version 2.1.0.

## Recommendation

- Upgrade Konga to version 2.1.0 or later immediately to resolve the insecure library loading behavior.
- Implement monitoring for the creation of directories within application-specific paths or known high-risk writeable locations by non-administrative users.
- Audit Windows service configurations to ensure that services running with elevated privileges are not susceptible to DLL hijacking or library loading vulnerabilities.
