---
title: Azure Monitor Agent Deserialization Vulnerability (CVE-2026-32192) Allows Local Privilege Escalation
slug: 2026-04-azure-monitor-agent-privilege-escalation
description: CVE-2026-32192 allows a locally authorized attacker to escalate privileges on a host running the Azure Monitor Agent via deserialization of untrusted data.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - cve-2026-32192
  - azure
  - monitor agent
  - privilege escalation
  - deserialization
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32192
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32192
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32192
rules:
  - title: Detect Suspicious Azure Monitor Agent Process Creation
    description: Detects unusual process creation events originating from the Azure Monitor Agent, potentially indicating exploitation of CVE-2026-32192.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Azure Monitor Agent Launching Cmd
    description: Detects Azure Monitor Agent launching command interpreter.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32192 is a critical vulnerability affecting the Azure Monitor Agent, a component used for collecting monitoring data in Azure environments. This vulnerability stems from the insecure deserialization of untrusted data, allowing an attacker with local access and authorization to escalate their privileges on the affected system. The vulnerability was published on April 14, 2026. An attacker could potentially leverage this to gain higher-level access to the system, potentially leading to…
