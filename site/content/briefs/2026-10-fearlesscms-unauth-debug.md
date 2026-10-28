---
brief_id: brief-2026-10-28-fearlesscms-unauth-debug
event_id: brief-2026-10-28-fearlesscms-unauth-debug
revision: 1
activity_at: "2026-10-28T23:36:52Z"
title: 'FearlessCMS: Unauthenticated debug script RCE and information disclosure (CVE-2026-63190)'
slug: 2026-10-fearlesscms-unauth-debug
description: CVE-2026-63190 allows unauthenticated attackers to bypass authentication via path normalization discrepancies to execute arbitrary filesystem operations, read sensitive files, and perform stored XSS in FearlessCMS versions prior to 0.1.4.
date: "2026-10-28T23:36:52Z"
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
  validation_status: Rule defined; environment validation required.
cpes:
  - cpe:2.3:a:fearlessgeekmedia:fearlesscms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - cms
  - remote-code-execution
  - cve
vendors:
  - FearlessCMS
products:
  - FearlessCMS (< 0.1.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated debug scripts in FearlessCMS allow filesystem operations and XSS.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attacker-controlled path and content reach file_put_contents for arbitrary .md writes... enabling site defacement.
    confidence_band: high
cves:
  - id: CVE-2026-63190
    cvss: 9.4
    kev_status: "false"
references:
  - https://github.com/fearlessgeekmedia/FearlessCMS/security/advisories/GHSA-3mq8-hrhf-7hv6
  - https://github.com/fearlessgeekmedia/FearlessCMS/commit/59fb22cf989b5ba14c387c3212e15b146e02cf9a
  - https://sploitus.com/exploit?id=CVE-2026-63190&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-63190 Exploitation - Authentication Bypass via Path Normalization
    description: Detects exploitation attempts targeting FearlessCMS debug scripts by identifying common path traversal patterns used to bypass administrative URI prefix checks.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade FearlessCMS to version 0.1.4 on all exposed instances.
      owner: IT Operations
      due: 24h
      evidence: Fixed in version 0.1.4.
  hunt_leads:
    - lead: Search web server access logs for '/./admin/' or unexpected access to files within the 'admin/' directory.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: router.php checks an unnormalized admin URI prefix while the filesystem resolves dot segments.
  mitigation_plan:
    - priority: immediate
      action: Upgrade FearlessCMS to 0.1.4.
      owner: IT Operations
      addresses: CVE-2026-63190
      evidence: This issue is fixed in version 0.1.4.
---

FearlessCMS versions prior to 0.1.4 contain five unauthenticated debug scripts within the 'admin/' directory. An authentication bypass exists due to inconsistent handling of unnormalized URI prefixes (e.g., using '/./admin/'), which allows attackers to reach these scripts despite authentication gates. These endpoints enable arbitrary filesystem reads and writes, stored XSS, and disk exhaustion. The vulnerability is fixed in version 0.1.4.

## Attack Chain
1. Attacker crafts an HTTP request using an unnormalized path (e.g., '/./admin/debug_save_flow.php') to bypass authentication checks in 'router.php'.
2. The application serves the requested debug script with administrative privileges.
3. Attacker uses 'admin/debug_save_flow.php' to perform path traversal and arbitrary file writes ('file_put_contents') to inject malicious content or stored XSS payloads.
4. Attacker uses 'admin/debug_content.php' to enumerate directories and read sensitive files via 'scandir' and 'file_get_contents'.
5. Attacker utilizes 'admin/preview-handler.php' or 'admin/testdebug.php' to induce disk exhaustion by writing excessive data to the server.
6. Stored XSS payloads execute in the context of administrators who view the manipulated content, potentially leading to session hijacking.

## Impact
Successful exploitation allows site defacement, unauthorized access to sensitive application data, potential session compromise via XSS, and service disruption through disk exhaustion. In default deployments where the application runs as root, these operations may result in full system compromise.

## Recommendation
- Upgrade FearlessCMS to version 0.1.4 or later immediately.
- Audit logs for requests containing suspicious directory traversal sequences such as '/./admin/' or '..' in URI stems.
- Review all contents of the 'content/' directory for unauthorized modifications or embedded JavaScript.
