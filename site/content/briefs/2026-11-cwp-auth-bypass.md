---
brief_id: brief-2026-11-02-cwp-auth-bypass
event_id: brief-2026-11-02-cwp-auth-bypass
revision: 3
activity_at: "2026-11-02T19:50:24Z"
revision_history:
  - revision: 2
    at: "2026-11-02T17:51:47Z"
    checksum: sha256:f6a1d5bce7796a284a69c25c79adf376c7f4fe2bc139550063153ab2ea5d8f3c
    summary: added CVE-2026-77877
    changed_fields:
      - action_plan
      - affected_products
      - claim_state
      - cves
      - lastmod
      - priority_signals
      - references
      - rules
      - tags
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-77877
  - revision: 3
    at: "2026-11-02T19:50:24Z"
    checksum: sha256:ed46f00d34b00315e444b952795aa64cf89fd06b2077e1be6ebae8078c18bd46
    summary: added CVE-2026-77878
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-77878
title: 'Control Web Panel: Authentication bypass via execution after redirect (CVE-2026-73696)'
slug: 2026-11-cwp-auth-bypass
description: Control Web Panel versions prior to 1.12 contain an execution after redirect vulnerability in the user panel authentication flow that allows attackers with a valid username to bypass authentication and achieve unauthorized code execution.
date: "2026-11-02T15:47:47Z"
lastmod: "2026-11-02T19:48:12Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for deployment
cpes:
  - cpe:2.3:a:control-webpanel:control_web_panel:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - rce
  - command-injection
vendors:
  - Control Web Panel
products:
  - Control Web Panel (< 1.12)
  - Control Web Panel (< 1.30)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers with nothing more than a valid hosting username can bypass authentication to reach user-panel module code paths, enabling a pre-authentication chain to root access.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: allowing PHP execution to continue and the module dispatcher include to run without authentication. Attackers with nothing more than a valid hosting username can bypass authentication to reach user-panel module code paths, enabling a pre-authentication chain to root access.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
    evidence: The /valid_token/ route allows unauthenticated attackers to execute arbitrary commands as root by injecting shell metacharacters.
    confidence_band: high
cves:
  - id: CVE-2026-73696
    cvss: 9.8
    kev_status: "false"
  - id: CVE-2026-104080
    cvss: 8.4
    kev_status: "false"
  - id: CVE-2026-77877
    cvss: 8.4
    kev_status: "false"
  - id: CVE-2026-77878
    cvss: 8.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73696
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104080
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77877
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77878
rules:
  - title: Detects CVE-2026-104080 Exploitation - Unauthenticated OS Command Injection
    description: Detects exploitation attempts against the CWP /valid_token/ route by looking for shell metacharacters in the user parameter
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Control Web Panel to version 1.12 or higher
      owner: IT Operations
      due: 24h
      evidence: Control Web Panel (CWP) before webpanel_version 1.12 contains an execution after redirect vulnerability
    - action: Patch Control Web Panel to version 1.30 or later
      owner: IT Operations
      due: 24h
      evidence: Control Web Panel (CWP) before webpanel_version 1.30 contains an OS command injection vulnerability
  hunt_leads:
    - lead: Identify access attempts to user-panel modules from accounts that lack successful authentication headers or sessions
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: the module dispatcher include to run without authentication
    - lead: Hunt for suspicious activity logs on CWP servers specifically targeting the /valid_token/ path
      technique_id: T1190
      data_needed:
        - Web access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Unauthenticated attackers can send a crafted request to the /valid_token/ route
  mitigation_plan:
    - priority: immediate
      action: Upgrade to CWP version 1.12
      owner: IT Operations
      addresses: CVE-2026-73696
      evidence: Control Web Panel (CWP) before webpanel_version 1.12 contains an execution after redirect vulnerability
    - priority: immediate
      action: Upgrade CWP to version 1.30
      owner: IT Operations
      addresses: CVE-2026-104080
      evidence: Control Web Panel (CWP) before webpanel_version 1.30 contains an OS command injection vulnerability
updates:
  - at: "2026-11-02T17:49:42Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-104080 Exploitation - Unauthenticated OS Command Injection'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104080
  - at: "2026-11-02T17:49:43Z"
    level: L2
    summary: added CVE-2026-77877
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-77877
  - at: "2026-11-02T19:48:12Z"
    level: L2
    summary: added CVE-2026-77878
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-77878
---

Control Web Panel (CWP) versions before 1.12 are vulnerable to an execution after redirect flaw within the user panel authentication process. The unauthenticatedFlow() function in CWPUserIndex initiates a redirect to the login page via toLoginWithIntendedUri() but fails to call exit(), which allows the PHP script execution to proceed. This flaw permits an attacker with a valid hosting username to reach module code paths that should be restricted, potentially leading to unauthorized access and privilege escalation.

## Impact

Successful exploitation allows unauthenticated users with a valid hosting account to bypass security controls and interact with internal user-panel modules, which can facilitate a chain of exploitation leading to root-level compromise of the server.

## Recommendation

Update all Control Web Panel instances to version 1.12 or later immediately to address the vulnerable authentication logic.
