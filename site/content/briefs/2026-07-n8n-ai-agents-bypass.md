---
title: n8n AI Agents Module Restriction Bypass via MCP Connector (CVE-2026-59207)
slug: 2026-07-n8n-ai-agents-bypass
description: The n8n AI Agents module in versions prior to 2.27.4 and between 2.28.0 and 2.28.1 failed to enforce configured 'Allowed HTTP Request Domains' restrictions, allowing an authenticated member-level user with 'use-only' access to a shared credential to bypass these domain restrictions and exfiltrate sensitive secrets to an attacker-controlled server.
date: "2026-07-22T21:59:10Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:n8n:n8n:*:*:*:*:*:node.js:*:*
  - cpe:2.3:a:n8n:n8n:2.28.0:*:*:*:*:node.js:*:*
tags:
  - vulnerability
  - n8n
  - restriction-bypass
  - data-exfiltration
  - ai-agents
vendors:
  - n8n GmbH
products:
  - n8n (>= 2.28.0, < 2.28.1)
  - n8n (< 2.27.4)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: cause its secret to be sent to an external server they control
    confidence_band: high
cves:
  - id: CVE-2026-59207
    cvss: 6.5
    epss: 0.00263
references:
  - https://github.com/advisories/GHSA-h44j-f5r5-ph73
---

The GHSA-h44j-f5r5-ph73 advisory details CVE-2026-59207, a restriction bypass vulnerability in the n8n automation platform's AI Agents module. Versions prior to 2.27.4 and versions 2.28.0 up to, but not including, 2.28.1 are affected. This flaw allows an authenticated member-level user, who has 'use-only' access to a shared credential with configured domain restrictions, to bypass these restrictions. By leveraging an AI Agent's Multi-Modal Communication Protocol (MCP) tool and directing it to an arbitrary external URL, the user can force the n8n instance to send sensitive secrets from the restricted credential to an attacker-controlled server. This vulnerability facilitates unauthorized data exfiltration, compromising the confidentiality of sensitive information. The issue is contingent on the `N8N_ENABLED_MODULES=agents` environment variable being active and a relevant credential being shared.

## Attack Chain

1. An authenticated member-level user gains 'use-only' access to a shared n8n credential that has configured "Allowed HTTP Request Domains" restrictions.
2. The attacker creates an AI Agent within the n8n instance.
3. The attacker configures the AI Agent to utilize an MCP tool.
4. The attacker points the MCP tool to an arbitrary, attacker-controlled external URL.
5. The attacker runs the AI Agent, which attempts to communicate with the external URL using the shared credential.
6. Due to the vulnerability (CVE-2026-59207), the n8n AI Agents module fails to enforce the domain restrictions.
7. The sensitive secret from the shared credential is sent to the attacker-controlled external server.
8. The attacker successfully exfiltrates the credential's secret.

## Impact

The successful exploitation of CVE-2026-59207 leads to the unauthorized exfiltration of sensitive secrets, such as API keys, database credentials, or other authentication tokens stored within n8n credentials. While the advisory does not specify the number of victims or targeted sectors, any organization using n8n with the AI Agents module enabled and shared restricted credentials is at risk. If an attacker gains access to these secrets, they can use them to access other internal or external systems, escalate privileges, or further compromise the organization's infrastructure, leading to significant data breaches and potential financial or reputational damage.

## Recommendation

* Patch CVE-2026-59207 immediately by upgrading n8n instances to version 2.28.1 or later, or 2.27.4 or later, to address the vulnerability in the affected_products.
* If immediate upgrade is not possible, disable the AI Agents module by removing `agents` from the `N8N_ENABLED_MODULES` environment variable to mitigate the risk.
* Audit and restrict credential sharing to fully trusted users only to minimize the blast radius of similar vulnerabilities.
* Review existing n8n credentials with domain restrictions for any unexpected sharing relationships.
