---
title: Unauthenticated Remote Code Execution in HFS2 via Template Injection
slug: 2026-09-hfs2-template-injection
description: HFS2 version 2.4.0 and earlier contains a template injection vulnerability in the multipart upload handler that allows unauthenticated attackers to achieve remote code execution.
date: "2026-09-24T14:46:53Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:hfs:hfs2:*:*:*:*:*:*:*:*
vendors:
  - HFS
products:
  - HFS2 (<= 2.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: HFS2 version 2.4.0 and earlier contains a template injection vulnerability in the multipart upload handler that allows unauthenticated attackers to achieve remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft a filename containing a closing template quoting sequence followed by an exec macro... to execute arbitrary commands.
    confidence_band: high
cves:
  - id: CVE-2026-97359
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97359
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade HFS2 to a version later than 2.4.0.
      owner: IT Operations
      due: 24h
      evidence: Source identifies 2.4.0 and earlier as vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the multipart upload handler via WAF or network perimeter security.
      owner: IT Operations
      addresses: CVE-2026-97359
      evidence: Vulnerability exists in the multipart upload handler.
---

HFS2 version 2.4.0 and earlier contains a template injection vulnerability within its multipart upload handler. An unauthenticated attacker can exploit this flaw by crafting a filename containing a malicious template quoting sequence followed by an exec macro. This vulnerability allows the attacker to bypass authorization checks within the application's dispatcher mechanism, resulting in remote code execution (RCE) on the underlying host system. Given the nature of the flaw, successful exploitation leads to full compromise of the server. Organizations running affected versions of HFS2 are at high risk and should prioritize remediation or apply necessary access controls to restrict access to the upload functionality until a patch is applied.

## Impact

Successful exploitation results in arbitrary remote code execution on the host system, granting the attacker the permissions of the user running the HFS2 application. This vulnerability poses a severe threat to any environment hosting HFS2, potentially leading to total system takeover, data exfiltration, and further lateral movement within the network.

## Recommendation

Prioritize the upgrade of all HFS2 installations to a patched version beyond 2.4.0. If immediate patching is not possible, restrict access to the multipart upload endpoint at the web application firewall or reverse proxy layer until remediation is complete.
