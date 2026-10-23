---
brief_id: brief-2026-10-collabora-code-rce
event_id: brief-2026-10-collabora-code-rce
revision: 3
activity_at: "2026-10-23T21:24:16Z"
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
  - revision: 3
    at: "2026-10-23T21:24:16Z"
    checksum: sha256:7528d90194ae7c025e34e056de003fb7cefcc917790b07222614676759ccfc50
    summary: new product
    changed_fields:
      - affected_products
      - content
      - cpes
      - exploitation_evidence
      - lastmod
      - priority_signals
      - references
      - summary
      - title
      - updates
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-110447
title: 'Collabora Online Built-in CODE Server: OS Command Injection (CVE-2026-110447)'
slug: 2026-10-collabora-code-rce
description: Collabora Online - Built-in CODE Server, when used within the NextCloud platform, contains an OS command injection vulnerability that allows for remote code execution when the CODE server is not running.
date: "2026-10-19T14:08:58Z"
lastmod: "2026-10-23T21:23:45Z"
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
  - cpe:2.3:a:collabora:online_built_in_code_server:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - web-application
vendors:
  - Collabora
products:
  - Collabora Online (< 26.4.303)
  - Collabora Online – Built-in CODE Server (< 26.4.303)
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
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110447
  - https://github.com/CollaboraOnline/online/security/advisories/GHSA-g3vx-3m76-fghh
  - https://help.nextcloud.com/t/to-collabora-built-in-user-update-asap/250516
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
  - https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk
  - https://www.cve.org/CVERecord?id=CVE-2026-110447
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
    summary: added CVE-2026-110447;
    sources:
      - cisa
    source_urls:
      - https://www.cisa.gov/news-events/alerts/2026/10/23/cisa-adds-one-known-exploited-vulnerability-catalog-0
  - at: "2026-10-23T21:23:45Z"
    level: L1
    summary: new product
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-110447
---

CVE-2026-110447 is an OS command injection vulnerability in the Collabora Online - Built-in CODE Server. The vulnerability occurs when the server is used within the NextCloud platform and the CODE server is not running, allowing for remote code execution.

## Recommendation
Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 guidance and CISA’s “Forensics Triage Requirements.” If mitigations are unavailable, discontinue use of the product. Stakeholders should evaluate asset internet exposure and ensure adherence to BOD 26-04 patching guidelines.
