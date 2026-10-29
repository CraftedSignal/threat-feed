---
brief_id: brief-2026-10-23-praisonai-auth-bypass
event_id: brief-2026-10-23-praisonai-auth-bypass
revision: 1
activity_at: "2026-10-23T13:40:25Z"
title: 'PraisonAI: Authorization bypass in approval backends (CVE-2026-56832)'
slug: 2026-10-praisonai-auth-bypass
description: PraisonAI versions 4.5.2 to before 4.6.59 contain an authorization bypass vulnerability in Discord, Slack, and Telegram approval backends, allowing unauthorized users to approve high-risk multi-agent tool calls.
date: "2026-10-23T13:40:25Z"
lastmod: "2026-10-29T19:57:40Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source verified; path traversal logic confirmed via NVD.
cpes:
  - cpe:2.3:a:praisonai:praisonai:*:*:*:*:*:*:*:*
  - cpe:2.3:a:praison:praisonai:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - api-security
  - praisonai
  - path-traversal
  - vulnerability
  - file-deletion
vendors:
  - PraisonAI
products:
  - PraisonAI (4.5.2 to before 4.6.59)
  - PraisonAI (3.8.1 - 4.6.58)
  - PraisonAI (>= 3.11.0, < 4.6.59)
  - PraisonAI (>= 4.5.112, < 4.6.59)
  - PraisonAI (>= 4.6.56, < 4.6.59)
  - PraisonAI (>= 4.5.87, < 4.6.59)
  - praisonai (4.5.2 to < 4.6.59)
  - PraisonAI (2.6.0 - 4.6.58)
  - PraisonAI (>= 4.5.126, < 4.6.59)
  - PraisonAI (>= 4.6.10, < 4.6.59)
  - PraisonAI (>= 4.5.87, < 4.6.61)
  - PraisonAI (>= 4.5.110, < 4.6.61)
  - PraisonAI (>= 4.5.115, < 4.6.61)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: As a result, any prompt/user/tool-caller that can influence those tool arguments can read files readable by the PraisonAI process, such as project .env files, cloud credentials, SSH keys, source files, or other local data.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: As a result, any prompt/user/tool-caller that can influence those tool arguments can read files readable by the PraisonAI process, such as project .env files, cloud credentials, SSH keys, source files, or other local data.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059.007
    technique_name: JavaScript
    evidence: An attacker-controlled tool argument can inject JavaScript into that page.
    confidence_band: high
cves:
  - id: CVE-2026-56832
    cvss: 8.8
    epss: 0.00148
    kev_status: "false"
  - id: CVE-2026-56834
    cvss: 7.5
    epss: 0.00373
    kev_status: "false"
  - id: CVE-2026-56835
    cvss: 8.3
    epss: 0.00215
    kev_status: "false"
  - id: CVE-2026-56836
    cvss: 8.2
    epss: 0.00227
    kev_status: "false"
  - id: CVE-2026-56837
    cvss: 8.6
    epss: 0.00188
    kev_status: "false"
  - id: CVE-2026-56838
    cvss: 7.8
    epss: 0.00146
    kev_status: "false"
  - id: CVE-2026-56840
    cvss: 8.8
    epss: 0.00375
    kev_status: "false"
  - id: CVE-2026-57113
    cvss: 8.1
    epss: 0.00405
    kev_status: "false"
  - id: CVE-2026-57114
    kev_status: unknown
  - id: CVE-2026-57117
    kev_status: unknown
  - id: CVE-2026-57142
    kev_status: unknown
  - id: CVE-2026-57144
    kev_status: unknown
  - id: CVE-2026-57146
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56832
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56834
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56835
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56836
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56837
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56838
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56840
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57113
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57114
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57117
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57142
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57144
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57146
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
    - SOC
  immediate_actions:
    - action: Upgrade PraisonAI to version 4.6.59 or later
      owner: IT Operations
      due: 48h
      evidence: This issue has been patched in version 4.6.59.
  hunt_leads:
    - lead: Search application logs for unusual artifact_path parameters containing traversal sequences such as ../
      technique_id: T1083
      data_needed:
        - Application logs capturing tool call arguments
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: the tools ... wrap the caller-supplied path directly into an ArtifactRef and then read it from the host filesystem.
    - lead: Identify PraisonAI processes running with the recipe serve command on non-localhost interfaces
      technique_id: T1190
      data_needed:
        - Host process monitoring (process command line)
        - Network listening port activity
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: That Typer command can start the Recipe HTTP server on a non-localhost interface with no authentication.
    - lead: Identify unauthorized tool approvals in application logs
      technique_id: T1059.007
      data_needed:
        - Application audit logs for /approve/{request_id}/decide
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: When a human opens the approval URL to inspect the risky tool request, the script runs in the dashboard origin and can POST to the same request's /approve/{request_id}/decide endpoint.
    - lead: Search application logs or process execution history for PraisonAI template resolution attempts containing directory traversal characters
      technique_id: T1059.003
      data_needed:
        - Application logs
        - Process command line arguments
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The resolver stores the user-controlled template path and ref verbatim... A crafted ref such as ../../../../../../outside-delete-target therefore escapes the cache directory.
  mitigation_plan:
    - priority: immediate
      action: Upgrade PraisonAI to version 4.6.59
      owner: IT Operations
      addresses: CVE-2026-56834
      evidence: This issue has been patched in version 4.6.59.
    - priority: immediate
      action: Restrict network access to PraisonAI ports via firewall or host-based ACLs
      owner: IT Operations
      addresses: CVE-2026-56836
      evidence: The server initializes on non-localhost interfaces without authentication.
    - priority: immediate
      action: Upgrade to version 4.6.59
      owner: IT Operations
      addresses: CVE-2026-57113
      evidence: This issue has been patched in version 4.6.59.
updates:
  - at: "2026-10-29T19:57:36Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-57114
  - at: "2026-10-29T19:57:37Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-57117
  - at: "2026-10-29T19:57:38Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-57142
  - at: "2026-10-29T19:57:39Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-57144
  - at: "2026-10-29T19:57:40Z"
    level: L1
    summary: new product
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-57146
---

PraisonAI, a multi-agent teams system, contains an authorization bypass vulnerability (CVE-2026-56832) affecting versions 4.5.2 to before 4.6.59. The issue involves the Discord, Slack, and Telegram messaging approval backends. In the Discord backend, any user who can post in the configured approval channel can approve a pending high-risk tool call by sending "yes" because the system does not require the message to be a reply or request-bound. Slack and Telegram backends lack an explicit approver allowlist parameter. This issue was patched in version 4.6.59.
