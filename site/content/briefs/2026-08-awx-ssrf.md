---
title: SSRF and Credential Leakage in AWX Notification Backends
slug: 2026-08-awx-ssrf
description: CVE-2026-71366 allows authenticated AWX notification administrators to perform SSRF and exfiltrate credentials by leveraging insufficient validation of notification template targets.
date: "2026-08-24T18:03:56Z"
lastmod: "2026-08-24T20:03:15Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - ssrf
  - credential-leakage
  - path-traversal
  - arbitrary-file-write
  - remote-code-execution
  - cve-2026-71364
vendors:
  - Ansible
products:
  - AWX
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The webhook, Mattermost, Rocket.Chat, and Grafana notification backends use notification template URLs as direct HTTP request targets without validating the target address against private, loopback, or reserved IP ranges.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: the webhook notification backend follows HTTP redirects and resends configured Basic Authentication credentials to redirect targets regardless of host change, allowing an attacker to exfiltrate notification credentials
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098.004
    technique_name: SSH Authorized Keys
    evidence: An attacker who controls the archive content ... can achieve arbitrary file writes as the user performing the extraction, potentially leading to remote code execution through mechanisms such as ... SSH authorized keys.
    confidence_band: high
cves:
  - id: CVE-2026-71366
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71366
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71364
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit notification templates for internal or loopback IP targets
      owner: IT Operations
      due: 24h
      evidence: Organization notification administrator can create notification templates pointing to internal or loopback addresses
  mitigation_plan:
    - priority: immediate
      action: Configure egress network policy to restrict AWX control node traffic to known/required notification endpoints
      owner: IT Operations
      addresses: CVE-2026-71366
      evidence: The vulnerability arises because notification template URLs are not validated against restricted IP ranges
updates:
  - at: "2026-08-24T20:03:15Z"
    level: L2
    summary: added coverage for AWX
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71364
---

CVE-2026-71366 describes a critical server-side request forgery (SSRF) vulnerability impacting multiple notification backends within AWX, including Webhook, Mattermost, Rocket.Chat, and Grafana. The vulnerability exists because the application fails to validate user-supplied notification template URLs against private, loopback, or reserved IP ranges. 

An attacker with notification administrator privileges can exploit this to force the AWX control node to perform HTTP requests against sensitive internal infrastructure or local services typically unreachable from the internet. The risk is compounded by secondary issues in the webhook backend, which follows HTTP redirects while improperly propagating configured Basic Authentication credentials to external, attacker-controlled hosts. Similarly, the Grafana backend exposes API keys in the Authorization header during these unauthorized requests. This issue enables both unauthorized internal network probing and the exfiltration of sensitive service credentials.

## Impact

Successful exploitation allows an authenticated administrator to bypass network access controls to probe internal services and exfiltrate authentication tokens, potentially leading to privilege escalation or lateral movement within the network.

## Recommendation

* Audit existing notification templates in AWX to identify URLs targeting internal network segments or loopback addresses.
* Implement strict egress filtering on the AWX control node to prevent unauthorized connections to internal resources.
* Rotate any credentials or API keys that have been configured in AWX notification templates, as these may have been exposed through the identified redirect and header leakage mechanisms.
* Apply vendor-supplied security patches for AWX to remediate the lack of URL validation.
