---
title: OS Command Injection in Checkov by Prisma Cloud
slug: 2026-09-0302-checkov-injection
description: CVE-2026-0302 allows local users with low privileges to achieve OS command injection by influencing input consumed during Checkov scanning processes.
date: "2026-09-09T18:57:51Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:palo_alto_networks:checkov_by_prisma_cloud:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - command-injection
  - prisma-cloud
vendors:
  - Palo Alto Networks
products:
  - Checkov by Prisma Cloud (3.2.0 - 3.2.501)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An OS command injection vulnerability in Palo Alto Networks Checkov by Prisma Cloud enables a local user to execute arbitrary commands in the processes running Checkov.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0302
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Checkov by Prisma Cloud to version 3.2.502 or later.
      owner: IT Operations
      due: 7d
      evidence: Solution section of the vendor advisory states to upgrade to 3.2.502 or later.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Checkov by Prisma Cloud to 3.2.502 or later.
      owner: IT Operations
      addresses: CVE-2026-0302
      evidence: Vendor advisory guidance.
---

Palo Alto Networks has disclosed an OS command injection vulnerability (CVE-2026-0302) affecting Checkov by Prisma Cloud versions 3.2.0 through 3.2.501. The vulnerability is classified under CWE-78: Improper Neutralization of Special Elements used in an OS Command. It enables a local, low-privileged user to execute arbitrary commands within the context of the running Checkov process. 

The exploitation requires the attacker to influence the input consumed by a Checkov scan. While the vulnerability is classified with a low severity score, successful exploitation leads to high integrity and confidentiality impact on the affected environment. Palo Alto Networks is currently unaware of any active malicious exploitation of this issue. Users are advised to upgrade to version 3.2.502 or later to remediate the vulnerability, as no workarounds are available.

## Impact

Successful exploitation of this vulnerability allows a local user to execute arbitrary commands with the privileges of the Checkov process. This can lead to unauthorized access to sensitive data, modification of infrastructure-as-code files, or further escalation within the host environment. The impact on confidentiality and integrity is high.

## Recommendation

* Upgrade all instances of Checkov by Prisma Cloud to version 3.2.502 or later immediately.
* Audit build pipelines and local scanning workflows that process untrusted configuration files.
* Restrict access to Checkov execution environments to trusted users only, as the vulnerability requires local access to influence scan inputs.
