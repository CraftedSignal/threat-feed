---
title: Progress Autonomous REST Connector GenAI Agents Vulnerability
slug: 2026-10-progress-arcgenai
description: Progress Software has released a security advisory regarding CVE-2026-91140, a critical vulnerability affecting the ARCGenAI-Generator component in versions prior to 2.1.
date: "2026-10-07T04:37:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:progress:autonomous_rest_connector_genai_agents_arcgenai_generator:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - cve-2026-91140
  - supply-chain
vendors:
  - Progress
products:
  - Autonomous REST Connector GenAI Agents ARCGenAI-Generator (< 2.1)
cves:
  - id: CVE-2026-91140
    cvss: 9.6
references:
  - https://cyber.gc.ca/en/alerts-advisories/progress-security-advisory-av26-1005
  - https://community.progress.com/s/article/Progress-DataDirect-Critical-Security-Alert-Bulletin-September-2026-CVE-2026-91140
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade ARCGenAI-Generator to version 2.1 or later
      owner: IT Operations
      addresses: CVE-2026-91140
      evidence: Progress Security Advisory AV26-1005
---

Progress Software has disclosed a critical security vulnerability, identified as CVE-2026-91140, impacting the Autonomous REST Connector GenAI Agents (ARCGenAI-Generator) product. This vulnerability affects all versions of the product prior to 2.1. The flaw was detailed in a security bulletin published in September 2026. Given the nature of the software, which facilitates connectivity for Generative AI agents, this vulnerability could potentially lead to unauthorized access or manipulation of data streams if successfully exploited. Administrators are advised to apply the mandatory updates provided by Progress to secure their deployments against this risk.

## Impact

The vulnerability poses a significant risk to organizations integrating ARCGenAI-Generator into their AI infrastructure. Successful exploitation could compromise the integrity and confidentiality of the data being processed or transmitted by the GenAI agents, potentially leading to unauthorized information disclosure or service disruption within the enterprise network.

## Recommendation

- Upgrade Progress Autonomous REST Connector GenAI Agents ARCGenAI-Generator to version 2.1 or later immediately.
- Review the Progress DataDirect Critical Security Alert Bulletin for specific guidance on CVE-2026-91140.
- Audit network logs for anomalous traffic patterns originating from or destined for servers hosting the ARCGenAI-Generator component.
