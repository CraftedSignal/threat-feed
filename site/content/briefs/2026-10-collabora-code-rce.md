---
brief_id: brief-2026-10-collabora-code-rce
event_id: brief-2026-10-collabora-code-rce
revision: 2
activity_at: "2026-10-23T20:29:43Z"
revision_history:
  - revision: 2
    at: "2026-10-23T20:29:43Z"
    checksum: sha256:aa93e6159eeff85f9f827255733f7cb46e1ce8383a6a9fdb3ab542dd2f68c7a6
    summary: added CVE-2026-110447; collabora online version < 26.4.303
    changed_fields:
      - action_plan
      - affected_products
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/news-events/alerts/2026/10/23/cisa-adds-one-known-exploited-vulnerability-catalog-0
title: Remote Code Execution Vulnerability in Collabora Online
slug: 2026-10-collabora-code-rce
description: Collabora Online contains a critical vulnerability that allows an unauthenticated, remote attacker to execute arbitrary code with the privileges of the web server user.
date: "2026-10-19T14:08:58Z"
lastmod: "2026-10-23T20:29:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:collabora:online:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application
vendors:
  - Collabora
products:
  - Collabora Online (< 26.4.303)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ein entfernter, anonymer Angreifer kann eine Schwachstelle in Collabora Collabora Online ausnutzen
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Schwachstelle ermöglicht Ausführen von beliebigem Programmcode mit Benutzerrechten
    confidence_band: high
cves:
  - id: CVE-2026-110447
    epss: 0.01225
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4011
  - https://www.cisa.gov/news-events/alerts/2026/10/23/cisa-adds-one-known-exploited-vulnerability-catalog-0
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch Collabora Online to 26.4.303 or later
      owner: IT Operations
      due: 24h
      evidence: Critical vulnerability allows RCE via unauthenticated request
  hunt_leads:
    - lead: Web server processes (e.g., apache, nginx, php-fpm) spawning shells or network utilities
      technique_id: T1059
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows execution of arbitrary code with web server user privileges
  mitigation_plan:
    - priority: immediate
      action: Apply the latest security updates provided by Collabora for the CODE server
      owner: IT Operations
      addresses: Collabora Online RCE vulnerability
      evidence: Source advisory indicates a code execution flaw exists
updates:
  - at: "2026-10-23T20:29:11Z"
    level: L2
    summary: added CVE-2026-110447; collabora online version < 26.4.303
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/alerts/2026/10/23/cisa-adds-one-known-exploited-vulnerability-catalog-0
---

Collabora Online has disclosed a critical security vulnerability affecting its built-in CODE server, often deployed within platforms such as Nextcloud. The vulnerability allows a remote, unauthenticated attacker to execute arbitrary program code on the underlying host. The code executes with the same privileges as the web server user, which typically corresponds to the service account running the Collabora Online or web server process (e.g., www-data or similar). Because the vulnerability does not require authentication, it represents a high risk to organizations exposing these collaboration tools to the internet. Defenders should prioritize identifying instances of Collabora Online and monitoring for unauthorized processes spawned by the web server service account.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing Collabora Online or Nextcloud instances.
2. Attacker sends a crafted, unauthenticated HTTP request to the vulnerable CODE server endpoint.
3. The request exploits an input validation or handling flaw in the Collabora Online service.
4. The exploit triggers the execution of arbitrary commands or code within the server memory.
5. The web server process executes the malicious payload using the service account permissions.
6. The attacker may establish a web shell or a reverse shell to maintain access.
7. Final objective: full compromise of the web server context, data exfiltration, or lateral movement into the hosting environment.

## Impact

Successful exploitation allows for full Remote Code Execution (RCE) on the server hosting the Collabora Online instance. This can lead to total system compromise, theft of sensitive documents stored within the collaborative environment, or the use of the server as a pivot point into the internal network. Organizations in all sectors using Collabora Online for document collaboration are at risk.

## Recommendation

- Monitor web server access logs for anomalous HTTP requests targeting CODE server endpoints, specifically those containing suspicious parameters or shell metacharacters.
- Audit all internet-facing instances of Collabora Online and restrict access to authorized IP ranges where possible.
- Enable process creation logging (e.g., Sysmon Event ID 1) for the web server service account to detect unexpected child processes (e.g., /bin/sh, /bin/bash, curl, or wget) spawned by the web server process.
- Monitor for unauthorized file modifications or the creation of new files within the document storage directories associated with the collaboration platform.
