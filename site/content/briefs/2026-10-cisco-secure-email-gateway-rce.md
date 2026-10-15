---
title: Critical RCE Vulnerability in Cisco Secure Email Gateway
slug: 2026-10-cisco-secure-email-gateway-rce
description: Cisco Secure Email Gateway contains a critical vulnerability in the Advanced Malware Protection (AMP) feature allowing unauthenticated remote code execution with root privileges, which is currently being exploited in the wild.
date: "2026-10-15T10:22:06Z"
lastmod: "2026-10-15T16:48:47Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - remote-code-execution
  - cisco
  - vulnerability
  - active-exploitation
  - path-traversal
  - rce
vendors:
  - Cisco
products:
  - Secure Email Gateway (AMP feature)
  - Secure Email Gateway (AsyncOS < 15.5.5-014, < 16.5.0-780, Content Scanner Tools < 25.3.0.5525)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability could allow an unauthenticated, remote attacker to write arbitrary files and execute commands.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The vulnerability could allow an unauthenticated, remote attacker to... execute commands with root privileges on the underlying operating system.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Cisco confirms that attackers can use the weakness to execute commands with root privileges on the operating system.
    confidence_band: high
references:
  - https://cert.europa.eu/publications/security-advisories/2026-017/
  - https://socprime.com/blog/cve-2026-76519-analysis/
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Cisco AsyncOS Software or Content Scanner Tools to patched versions.
      owner: IT Operations
      due: 24h
      evidence: CERT-EU recommends updating the Content Scanner Tools package or upgrading Cisco AsyncOS Software.
  mitigation_plan:
    - priority: immediate
      action: Patch appliance for CVE-2026-017
      owner: IT Operations
      addresses: CVE-2026-017
      evidence: Cisco PSIRT advisory/CERT-EU publication
updates:
  - at: "2026-10-15T16:48:47Z"
    level: L2
    summary: added coverage for Secure Email Gateway (AsyncOS < 15.5.5-014, < 16.5.0-780, Content Scanner Tools < 25.3.0.5525)
    sources:
      - socprime
    source_urls:
      - https://socprime.com/blog/cve-2026-76519-analysis/
---

On 14 October 2026, Cisco disclosed a critical vulnerability (CVE-2026-017) affecting the Advanced Malware Protection (AMP) feature within Cisco Secure Email Gateway. The vulnerability allows an unauthenticated, remote attacker to perform arbitrary file writes and execute commands as the root user on the underlying operating system. The Cisco PSIRT has confirmed that this vulnerability is currently being actively exploited in the wild. This represents a significant risk as it grants attackers full control over the appliance, which is typically positioned at the network perimeter. Given the active exploitation, immediate remediation is required for all internet-facing appliances.

## Impact

Successful exploitation results in full system compromise with root-level privileges. Attackers can gain persistent access to the email gateway, intercept or manipulate sensitive internal and external email traffic, and use the appliance as a pivot point for further lateral movement into the internal network. The scope of targeting includes all organizations utilizing Cisco Secure Email Gateway with the AMP feature enabled, particularly those with management or scanning interfaces reachable via the internet.

## Recommendation

* Prioritize patching for all Cisco Secure Email Gateway appliances exposed to the internet.
* Update the Content Scanner Tools package or upgrade Cisco AsyncOS Software to a release containing the fix for CVE-2026-017.
* Conduct forensic analysis on affected appliances to identify indicators of unauthorized access or malicious file artifacts resulting from the arbitrary file write capability.
* Review peripheral network access controls to restrict exposure of the Secure Email Gateway management interface.
