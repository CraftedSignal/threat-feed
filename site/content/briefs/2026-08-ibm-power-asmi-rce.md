---
title: Critical RCE Vulnerability in IBM Power Systems Firmware ASMI
slug: 2026-08-ibm-power-asmi-rce
description: IBM Power Systems Firmware contains a stack-based buffer overflow in the ASMI web interface, allowing an unauthenticated attacker to achieve arbitrary code execution on the Flexible Service Processor.
date: "2026-08-19T20:38:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - remote-code-execution
  - firmware
  - hardware
vendors:
  - IBM
products:
  - Power Systems Firmware
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker with network access can send the FSP a malformed request, allowing arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: allowing arbitrary code execution, giving the attacker full control over the managed system
    confidence_band: high
cves:
  - id: CVE-2026-16687
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16687
  - https://www.ibm.com/support/pages/node/7283893
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch firmware per IBM security bulletin for CVE-2026-16687
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-16687
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to ASMI management interfaces via firewall or VLAN isolation
      owner: IT Operations
      addresses: CVE-2026-16687
      evidence: NVD vulnerability description
---

IBM has disclosed a critical security vulnerability, identified as CVE-2026-16687, affecting the Advanced System Management Interface (ASMI) of various Power Systems firmware versions. The vulnerability, classified as a stack-based buffer overflow (CWE-121), stems from improper validation of input within the web interface of the Flexible Service Processor (FSP). An unauthenticated attacker with network access to the ASMI management interface can send a malformed request, leading to memory corruption. This allows for arbitrary code execution, granting the attacker full control over the managed hardware system. Given the nature of FSP access, successful exploitation results in total loss of confidentiality, integrity, and availability for the affected Power Systems server. The vulnerability affects firmware versions in the FW1120.00, FW1110.xx, FW1060.xx, and FW950.xx series.

## Impact

Successful exploitation allows an unauthenticated attacker to execute code with the privileges of the FSP, effectively gaining total control over the physical server management functions. This level of access permits unauthorized monitoring, data exfiltration, permanent disabling of the system, or the ability to bypass operating system security controls. The vulnerability impacts enterprise environments utilizing IBM Power Systems for critical infrastructure and mission-critical workloads.

## Recommendation

Prioritized, concrete actions for security and infrastructure teams:
- Immediately identify all IBM Power Systems hardware within the environment and verify the currently installed firmware version against the affected releases (FW1120.00, FW1110.00-30, FW1060.00-80, FW950.00-H2).
- Apply the vendor-provided firmware updates listed in the official IBM security bulletin (referenced below) as the primary remediation.
- Implement network segmentation to restrict access to the ASMI/FSP management interfaces, ensuring they are only accessible from secure, authorized management networks or dedicated VLANs.
- Disable public or wide-area network access to the FSP interface immediately.
- Monitor logs for unusual HTTP traffic directed toward the ASMI/FSP management interface, particularly requests containing abnormally large payloads or non-standard characters, which may indicate attempted exploitation of CVE-2026-16687.
