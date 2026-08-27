---
title: SSRF Vulnerability in RAGFlow Agent Workflow
slug: 2026-08-ragflow-ssrf
description: RAGFlow before 0.26.3 contains a server-side request forgery (SSRF) vulnerability in the 'Invoke' component that allows attackers to access sensitive internal network resources and cloud metadata.
date: "2026-08-18T16:55:42Z"
lastmod: "2026-08-27T01:36:12Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0F12A135-B7F3-53D1-A985-FBC0FB786B9F&utm_source=rss&utm_medium=rss
tags:
  - ssrf
  - vulnerability
  - cloud-security
vendors:
  - RAGFlow
products:
  - RAGFlow (0.26.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A user who can create or trigger an agent can direct the server to fetch loopback, link-local, and RFC 1918 destinations.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: the response body is returned as the component output.
    confidence_band: high
cves:
  - id: CVE-2026-75898
    cvss: 8.5
    epss: 0.00297
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75898
  - https://sploitus.com/exploit?id=0F12A135-B7F3-53D1-A985-FBC0FB786B9F&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade RAGFlow instances to 0.26.3 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-75898 remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access for RAGFlow service containers via network security groups
      owner: IT Operations
      addresses: CVE-2026-75898
      evidence: Mitigation for SSRF against internal resources
updates:
  - at: "2026-08-27T01:36:12Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0F12A135-B7F3-53D1-A985-FBC0FB786B9F&utm_source=rss&utm_medium=rss
---

RAGFlow before version 0.26.3 is susceptible to a server-side request forgery (SSRF) vulnerability located in the agent workflow "Invoke" component (agent/component/invoke.py). The vulnerability stems from improper validation of user-controlled URLs before they are passed to request methods (requests.get, requests.post, or requests.put). Unlike other components in the system such as the crawler or file-upload paths, the Invoke component fails to utilize the shared assert_url_is_safe validator or pin the resolved address. An attacker capable of creating or triggering an agent workflow can coerce the server to perform requests against loopback interfaces, link-local addresses, and RFC 1918 internal networks. This includes the ability to exfiltrate data from cloud instance metadata services (e.g., AWS IMDS), as the response body from the forged request is returned directly to the user as the component output.

## Impact

Successful exploitation allows for the exfiltration of sensitive internal network data and cloud instance credentials. In cloud-hosted environments, attackers may query metadata endpoints to retrieve IAM roles or other configuration secrets, potentially leading to full cluster or cloud account compromise. The impact is significant because the application returns the forged request's response body directly to the attacker, facilitating easy data extraction.

## Recommendation

* Upgrade RAGFlow to version 0.26.3 or later immediately to patch the SSRF vulnerability in the agent/component/invoke.py file.
* Implement strict egress filtering on the host machine running RAGFlow to block requests to loopback (127.0.0.0/8) and private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) unless explicitly required for known internal services.
* Configure cloud instances (e.g., EC2, GCP Compute) to require IMDSv2 with a session token requirement to mitigate credential exfiltration via SSRF.
* Audit existing agent workflows for suspicious Invoke component configurations, specifically those pointing to internal endpoints or utilizing runtime template variables for URL construction.
