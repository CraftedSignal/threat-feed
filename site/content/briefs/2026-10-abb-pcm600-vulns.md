---
title: Privilege Escalation and Path Traversal Vulnerabilities in ABB PCM600
slug: 2026-10-abb-pcm600-vulns
description: ABB Protection and Control IED Manager PCM600 versions 2.14 and earlier contain local privilege escalation and path traversal vulnerabilities that could allow authenticated local attackers to gain unauthorized host control or overwrite files.
date: "2026-10-01T17:06:34Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - ABB
products:
  - Protection and Control IED Manager PCM600 (<=2.14)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker with local access and valid user credentials may exploit this vulnerability to elevate privileges and obtain control of the affected host.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-274-03
  - https://www.cve.org/CVERecord?id=CVE-2026-15952
  - https://www.cve.org/CVERecord?id=CVE-2026-15953
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-274-03.json
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Reconfigure ABBPCMSchedulerService to run under a standard user account per vendor mitigations
      owner: IT Operations
      due: 72h
      evidence: Source provides specific service configuration instructions
  mitigation_plan:
    - priority: immediate
      action: Isolate PCM600 workstations from public internet and business networks
      owner: IT Operations
      addresses: General ICS best practices
      evidence: CISA recommended practices section
---

ABB Protection and Control IED Manager PCM600 versions 2.14 and earlier are affected by two vulnerabilities that impact the security of the host system. CVE-2026-15952 involves the Scheduler Service, which executes with LocalSystem privileges but permits standard PCM600 users to interact with it, enabling local privilege escalation for attackers who already possess valid user credentials. Additionally, CVE-2026-15953 relates to the processing of PCM600 project archive files; insufficient input validation of pathnames within these archives permits path traversal, which could allow an attacker to write malicious files outside of the designated extraction directory. These vulnerabilities are particularly relevant for defenders managing energy sector infrastructure where PCM600 is deployed globally. While no active exploitation has been reported, these vulnerabilities pose a significant risk to host integrity and system-level security when an attacker has already established a foothold on the local machine.

## Impact

Successful exploitation of these vulnerabilities could result in full system compromise via privilege escalation or the unauthorized overwriting of critical system files via path traversal. This impacts energy sector organizations globally, potentially leading to the loss of integrity of the IED management platform and disruption of control system operations. There are no concrete numbers regarding current victim count, but the vulnerability is prevalent in environments running PCM600 version 2.14 or older.

## Recommendation

- Perform a risk assessment and impact analysis on all systems running ABB PCM600 version 2.14 or earlier.
- Implement the recommended workaround by reconfiguring the ABBPCMSchedulerService to execute under the same low-privileged Windows account used for the standard PCM600 application rather than LocalSystem.
- Ensure that the "Log on as a service" privilege is correctly assigned and limited to the specific service account.
- Restrict access to control system networks and ensure all IED management stations are isolated from internet access.
- When IED security certificates are in use, strictly limit the "Always trust IED security certificates" setting to trusted, secure communication environments.
