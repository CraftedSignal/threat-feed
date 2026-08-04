---
title: Path Traversal Vulnerability in Zyxel Network Appliance CLI
slug: 2026-08-zyxel-path-traversal
description: An authenticated path traversal vulnerability in Zyxel ATP and USG series firmware allows administrators to execute arbitrary configuration files, potentially leading to command execution.
date: "2026-08-04T06:12:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - network-security
  - firmware
vendors:
  - Zyxel
products:
  - ATP series
  - USG FLEX series
  - USG FLEX 50(W) series
  - USG20(W)-VPN series
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The CLI command handler responsible for processing configuration files allows an authenticated attacker to execute a crafted malicious configuration file.
    confidence_band: high
cves:
  - id: CVE-2026-14818
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14818
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch firmware to V5.42 Patch 2 or higher on all Zyxel appliances.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-14818 remediation documentation.
  mitigation_plan:
    - priority: immediate
      action: Restrict administrative access to authorized IP addresses.
      owner: Network Security
      addresses: CVE-2026-14818
      evidence: Vulnerability requires existing administrative access.
---

A path traversal vulnerability exists in the CLI command handler responsible for processing configuration files within Zyxel network security appliances. This vulnerability, tracked as CVE-2026-14818, affects the ATP series (versions V4.32 through V5.42 Patch 1), USG FLEX series (versions V4.50 through V5.42 Patch 1), USG FLEX 50(W) series (versions V4.16 through V5.42 Patch 1), and USG20(W)-VPN series (versions V4.16 through V5.42 Patch 1). An attacker who has already gained administrative authentication to the device can leverage this flaw to traverse directories and execute a specially crafted configuration file. Successful exploitation results in the execution of arbitrary commands, allowing the attacker to alter the device configuration or achieve persistent system access. Defenders should prioritize updating firmware to versions V5.42 Patch 2 or later, where this path handling logic has been remediated.
