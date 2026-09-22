---
title: Remote Code Execution in Barracuda Email Security Gateway
slug: 2026-09-barracuda-rce
description: A critical remote code execution vulnerability in Barracuda Email Security Gateway caused by improper input validation of email attachments allows attackers to execute arbitrary code.
date: "2026-09-22T13:56:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:barracuda:email_security_gateway:*:*:*:*:*:*:*:*
  - cpe:2.3:o:barracuda:email_security_gateway_300_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:barracuda:email_security_gateway_400_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:barracuda:email_security_gateway_600_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:barracuda:email_security_gateway_800_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:barracuda:email_security_gateway_900_firmware:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - network-security
vendors:
  - Barracuda Networks
products:
  - Email Security Gateway
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A critical vulnerability in the Barracuda Email Security Gateway allows remote attackers to execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The vulnerability exists due to improper input validation in the processing of email attachments, leading to remote code execution.
    confidence_band: high
cves:
  - id: CVE-2023-2868
    cvss: 9.4
    epss: 0.87691
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3491
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Barracuda Email Security Gateway to the latest version to address CVE-2023-2868.
      owner: IT Operations
      due: 24h
      evidence: CVE-2023-2868 vulnerability in Barracuda Email Security Gateway.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Barracuda Email Security Gateway to the vendor-recommended patched version.
      owner: IT Operations
      addresses: CVE-2023-2868
      evidence: BSI security advisory.
---

Barracuda Networks has identified a critical vulnerability in the Email Security Gateway that facilitates remote code execution (RCE). The flaw, tracked as CVE-2023-2868, arises from improper input validation when the appliance processes incoming email attachments. Attackers can leverage this vulnerability to execute arbitrary code on the target appliance by sending specially crafted email attachments. Given the position of these appliances at the network perimeter, successful exploitation grants an attacker full control over the gateway, enabling potential interception of email traffic, credential harvesting, or lateral movement into the internal network. Defenders should prioritize patching affected appliances immediately to mitigate the risk of exploitation.

## Impact

Successful exploitation of CVE-2023-2868 results in unauthenticated remote code execution on the Barracuda Email Security Gateway. This allows for total system compromise, including the potential for data exfiltration of sensitive communications and unauthorized access to protected internal resources within the enterprise network.

## Recommendation

Prioritize patching all internet-facing Barracuda Email Security Gateway appliances to the latest vendor-supplied version to remediate CVE-2023-2868.
