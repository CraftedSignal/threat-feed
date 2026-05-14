---
title: n8n XML Node Prototype Pollution Patch Bypass Leads to RCE
slug: 2026-05-n8n-xml-prototype-bypass
description: An authenticated n8n user with workflow creation privileges can bypass a previous patch for XML node prototype pollution, potentially leading to remote code execution on the n8n host when combined with other nodes; patched in versions 1.123.43, 2.20.7, and 2.22.1.
date: "2026-05-14T16:22:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - prototype pollution
  - RCE
  - n8n
  - CVE-2026-44791
vendors:
  - n8n GmbH
products:
  - n8n (< 1.123.43)
  - n8n (>= 2.21.0, < 2.22.1)
  - n8n (>= 2.0.0-rc.0, < 2.20.7)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
references:
  - https://github.com/advisories/GHSA-wrwr-h859-xh2r
  - CVE-2026-44791
rules:
  - title: Detect n8n XML Node Prototype Pollution Attempt
    description: Detects CVE-2026-44791 exploitation — Attempts to exploit prototype pollution via crafted XML workflows in n8n
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1210
    data_sources:
      - webserver
  - title: Detect n8n Execute Command Node Usage
    description: Detects the use of the n8n Execute Command node, potentially as part of an RCE chain.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 2
---

An authenticated user with permission to create or modify workflows can bypass the patch for GHSA-hqr4-h3xv-9m3r in the XML node of n8n, a workflow automation platform. This vulnerability, identified as CVE-2026-44791, allows for prototype pollution. Successful exploitation, when chained with other nodes, can lead to remote code execution (RCE) on the n8n host. The affected versions include n8n versions prior to 1.123.43, versions 2.21.0 to 2.22.1 (excluding 2.22.1), and versions 2.0.0-rc.0 to 2.20.7 (excluding 2.20.7). This vulnerability matters to defenders because it allows attackers to gain complete control over the n8n instance, potentially compromising sensitive data and enabling further malicious activities.

## Attack Chain

1. An attacker gains authenticated access to an n8n instance with workflow creation and modification privileges.
2. The attacker crafts a malicious workflow that includes the XML node.
3. The attacker exploits CVE-2026-44791, bypassing the patch for GHSA-hqr4-h3xv-9m3r by manipulating XML node parameters to inject a prototype pollution payload.
4. The prototype pollution modifies JavaScript object prototypes within the n8n environment.
5. The attacker chains the XML node with other nodes in the workflow (e.g., Function node, Execute Command node).
6. The polluted prototypes are leveraged by the subsequent nodes to execute arbitrary JavaScript code.
7. The arbitrary code execution allows the attacker to execute system commands on the n8n host.
8. The attacker achieves remote code execution (RCE), gaining control of the n8n host and potentially compromising the underlying system.

## Impact

Successful exploitation of CVE-2026-44791 allows an attacker to achieve remote code execution on the n8n host. This could lead to the complete compromise of the n8n instance, potentially affecting all workflows and data managed by the platform. The attacker could potentially access sensitive information, modify workflows for malicious purposes, or use the compromised host as a pivot point for further attacks within the network. The vulnerability affects n8n instances running vulnerable versions prior to the patched versions, impacting any organization using n8n for workflow automation.

## Recommendation

*   Upgrade n8n to version 1.123.43, 2.20.7, or 2.22.1 or later to remediate CVE-2026-44791, as mentioned in the overview.
*   Deploy the Sigma rule "Detect n8n XML Node Prototype Pollution Attempt" to identify suspicious workflow creations involving the XML node, as described in the rules section.
*   If immediate upgrade is not possible, implement the suggested workarounds by limiting workflow creation/editing permissions or disabling the XML node via the `NODES_EXCLUDE` environment variable, as detailed in the overview section.
