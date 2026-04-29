---
title: n8n MCP OAuth Client XSS Vulnerability
slug: 2026-05-n8n-xss-oauth
description: n8n is vulnerable to cross-site scripting (XSS) via a malicious MCP OAuth client, allowing an unauthenticated attacker to inject arbitrary JavaScript into an authenticated user's session.
date: "2026-04-29T21:25:44Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - xss
  - oauth
  - n8n
  - CVE-2026-42235
vendors:
  - npm
products:
  - n8n
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-537j-gqpc-p7fq
rules:
  - title: Detect Suspicious n8n MCP OAuth Client Registration
    description: Detects attempts to register n8n MCP OAuth clients with suspicious names containing potential XSS payloads.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Toast Notification Rendering XSS Payload
    description: Detects potential XSS exploitation via toast notifications rendering malicious client names.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

n8n, a workflow automation platform, is susceptible to a cross-site scripting (XSS) vulnerability (CVE-2026-42235) related to the registration of malicious MCP OAuth clients. An unauthenticated attacker can register an OAuth client with a crafted `client_name` containing malicious JavaScript. This vulnerability exists in versions prior to 2.14.2 and also affects versions 2.17.0 to 2.17.3 and 2.18.0. A successful exploit allows the attacker to execute arbitrary JavaScript within a victim's authenticated n8n session, potentially leading to credential theft, session token theft, workflow manipulation, or privilege escalation. Defenders should prioritize patching to version 2.14.2 or later to mitigate the risk.

## Attack Chain

1. An unauthenticated attacker registers a malicious MCP OAuth client with a crafted `client_name` containing XSS payload.
2. A victim user navigates to the n8n instance and is presented with the malicious OAuth consent dialog.
3. The victim user authorizes the malicious OAuth client, unknowingly injecting the attacker's script into their session.
4. A second user, possibly an administrator, revokes the OAuth access granted to the malicious client.
5. This revocation triggers a toast notification to the original victim user.
6. The toast notification renders the attacker's injected script from the crafted `client_name`.
7. The victim user clicks on the link within the toast notification.
8. The injected JavaScript executes within the victim's authenticated n8n browser session, enabling the attacker to perform malicious actions such as stealing credentials, manipulating workflows, or escalating privileges.

## Impact

Successful exploitation of this XSS vulnerability can lead to significant compromise of an n8n instance. Attackers can steal user credentials and session tokens, allowing them to impersonate legitimate users. Malicious actors could also modify or create workflows, leading to data breaches, system disruption, or unauthorized access. Privilege escalation is also possible, potentially granting attackers administrative control over the n8n platform. The number of potential victims depends on the exposure and user base of the vulnerable n8n instances.

## Recommendation

*   Upgrade n8n to version 2.14.2 or later to patch CVE-2026-42235, as recommended in the advisory.
*   Deploy the Sigma rule `Detect Suspicious n8n MCP OAuth Client Registration` to identify attempts to register OAuth clients with suspicious names.
*   If immediate patching is not feasible, restrict access to the n8n instance and the MCP OAuth registration endpoint to trusted users only, as suggested in the advisory's workaround.
