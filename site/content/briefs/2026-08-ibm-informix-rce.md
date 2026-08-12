---
title: Remote Code Execution in IBM Informix via sq_sgkprepare
slug: 2026-08-ibm-informix-rce
description: A critical buffer-related vulnerability (CVE-2026-13361) in IBM Informix allows remote, unauthenticated attackers to achieve code execution via the SQL interface by exploiting an unchecked length field in the oninit process.
date: "2026-08-12T20:52:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - vulnerability
  - database-security
vendors:
  - IBM
products:
  - Informix
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit this buffer-related vulnerability via the SQL interface to execute arbitrary code with the privileges of the Informix service.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can exploit this buffer-related vulnerability via the SQL interface to execute arbitrary code with the privileges of the Informix service.
    confidence_band: high
cves:
  - id: CVE-2026-13361
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13361
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch IBM Informix installations
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-13361 vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to SQL interface ports
      owner: IT Operations
      addresses: CVE-2026-13361
      evidence: Vulnerability requires access to the SQL interface
---

IBM Informix is affected by a critical remote code execution vulnerability (CVE-2026-13361) localized within the `sq_sgkprepare` function of the `oninit` process. The vulnerability stems from an unchecked length field handling mechanism when processing inputs through the SQL interface. This flaw allows a remote attacker to trigger a buffer overflow condition, resulting in the execution of arbitrary code with the privileges of the Informix service process. Given that `oninit` typically runs with elevated system privileges, successful exploitation provides an attacker with significant control over the underlying database server. Organizations using IBM Informix should prioritize patching or implementing compensating controls at the network boundary to restrict access to the SQL interface until remediation is complete.

## Impact

Successful exploitation of CVE-2026-13361 results in full remote code execution on the target IBM Informix server. An attacker gaining these privileges can exfiltrate sensitive database contents, modify records, or move laterally into the host environment, potentially compromising the entire database cluster.

## Recommendation

* Apply the security patches provided by IBM for the Informix product line immediately upon release.
* Restrict network access to the Informix SQL interface (default ports) to trusted management subnets using host-based or network firewalls to mitigate unauthenticated exploitation attempts.
* Implement egress filtering on the database server to prevent payloads from initiating secondary callback connections or downloading additional stages from the internet.
