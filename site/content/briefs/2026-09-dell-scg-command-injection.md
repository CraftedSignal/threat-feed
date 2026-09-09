---
title: Command Injection Vulnerability in Dell Secure Connect Gateway
slug: 2026-09-dell-scg-command-injection
description: Dell Secure Connect Gateway (SCG) contains a critical command injection vulnerability allowing unauthenticated remote attackers to perform script injection and potential unauthorized command execution.
date: "2026-09-09T21:02:07Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:dell:secure_connect_gateway:*:*:*:*:application:*:*:*
  - cpe:2.3:a:dell:secure_connect_gateway:*:*:*:*:virtual:*:*:*
vendors:
  - Dell
products:
  - Secure Connect Gateway (Appliance < 5.36.00.16)
  - Secure Connect Gateway (Application < 5.36.00.00)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker with remote access could potentially exploit this vulnerability.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Improper Neutralization of Special Elements used in a Command ('Command Injection') vulnerability.
    confidence_band: high
cves:
  - id: CVE-2026-79941
    cvss: 5.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79941
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Dell SCG Appliance to 5.36.00.16
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-79941 remediation path
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to SCG management ports
      owner: Network Security
      addresses: CVE-2026-79941
      evidence: Unauthenticated remote exploitation potential
---

Dell Secure Connect Gateway (SCG) versions 5.0 are affected by a critical command injection vulnerability identified as CVE-2026-79941. The flaw stems from improper neutralization of special elements used in system commands, enabling an unauthenticated remote attacker to inject malicious scripts. This vulnerability impacts both the SCG Appliance (fixed in version 5.36.00.16) and the SCG Application (fixed in version 5.36.00.00). Successful exploitation could allow an attacker to execute arbitrary commands within the context of the appliance or application, leading to a full compromise of the affected gateway. Given the administrative nature of SCG, which typically manages connectivity for hardware infrastructure, this represents a significant risk to the integrity of the network management environment.

## Impact

Successful exploitation of this vulnerability grants an unauthenticated attacker remote command execution capabilities on the affected Dell SCG appliance or application. This can lead to unauthorized access to management functions, potential exfiltration of sensitive configuration data, or lateral movement within the network from the compromised appliance. The vulnerability carries a CVSS v3.1 base score of 9.8, reflecting its high impact and ease of exploitability via remote, unauthenticated channels.

## Recommendation

- Upgrade all Dell Secure Connect Gateway (SCG) Appliance instances to version 5.36.00.16 or later.
- Upgrade all Dell Secure Connect Gateway (SCG) Application instances to version 5.36.00.00 or later.
- Restrict network access to the SCG web management interface to trusted administrative subnets only.
- Audit network logs for anomalous HTTP requests targeting the SCG management interface that utilize shell metacharacters or encoded payloads.
