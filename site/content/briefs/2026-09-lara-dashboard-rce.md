---
brief_id: brief-2026-09-07-lara-dashboard-rce
event_id: brief-2026-09-07-lara-dashboard-rce
revision: 2
activity_at: "2026-10-27T01:10:17Z"
revision_history:
  - revision: 2
    at: "2026-10-27T01:10:17Z"
    checksum: sha256:7956ceb3c49c0e62d5b3f8c4f0592e75b516de9cfe239e2e9408dcf365d83589
    summary: poc_available; added CVE-2026-90932 +1
    changed_fields:
      - affected_products
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - rules
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=11B69861-9369-53FF-ACD7-40634D64700A&utm_source=rss&utm_medium=rss
title: Arbitrary File Upload and RCE in Lara Dashboard
slug: 2026-09-lara-dashboard-rce
description: Lara Dashboard versions prior to 1.3.2 are vulnerable to arbitrary file upload via the core-upgrades endpoint, allowing unauthorized administrators to achieve remote code execution.
date: "2026-09-07T23:37:52Z"
lastmod: "2026-10-27T01:09:15Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=11B69861-9369-53FF-ACD7-40634D64700A&utm_source=rss&utm_medium=rss
tags:
  - web-application-vulnerability
  - rce
  - file-upload
  - path-traversal
  - web-vulnerability
vendors:
  - LaraDashboard
products:
  - Lara Dashboard (< 1.3.2)
  - LaraDashboard (0.9.2 - 1.2.2)
  - Laradashboard (<= 1.2.2)
  - LaraDashboard (>= 0.9.2, <= 1.2.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Lara Dashboard before 1.3.2 authorizes the POST /admin/settings/core-upgrades/upload endpoint with only the settings.edit permission.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can upload a malicious archive containing modified application files such as routes/web.php with embedded system commands.
    confidence_band: high
cves:
  - id: CVE-2026-86437
    cvss: 7.2
    epss: 0.00711
    kev_status: "false"
  - id: CVE-2026-90932
    cvss: 7.2
    epss: 0.0082
    kev_status: "false"
  - id: CVE-2026-90933
    cvss: 7.1
    epss: 0.00301
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86437
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90932
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90933
  - https://sploitus.com/exploit?id=11B69861-9369-53FF-ACD7-40634D64700A&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Lara Dashboard to version 1.3.2 or later.
      owner: IT Operations
      due: 24h
      evidence: Lara Dashboard before 1.3.2 authorizes the POST /admin/settings/core-upgrades/upload endpoint incorrectly.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Lara Dashboard to version 1.3.2.
      owner: IT Operations
      addresses: CVE-2026-86437
      evidence: NVD vulnerability report
updates:
  - at: "2026-09-14T13:34:15Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-90932 Exploitation - Path Traversal in Backup Parameters'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90932
  - at: "2026-09-14T13:34:23Z"
    level: L2
    summary: 'added detection rule: Detect Unauthorized Access to Laradashboard License API'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90933
  - at: "2026-10-27T01:09:15Z"
    level: L2
    summary: poc_available; added CVE-2026-90932 +1
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=11B69861-9369-53FF-ACD7-40634D64700A&utm_source=rss&utm_medium=rss
---

Lara Dashboard versions before 1.3.2 contain an authorization flaw in the /admin/settings/core-upgrades/upload endpoint. The application incorrectly restricts access to this endpoint to the 'settings.edit' permission rather than enforcing 'Superadmin' status. This vulnerability allows an authenticated administrator with limited permissions to upload and extract arbitrary ZIP archives. By crafting a malicious archive, an attacker can overwrite critical application files, such as 'routes/web.php', with payloads containing system commands. These commands execute in the context of the web server user, providing the attacker with full control over the application environment, including access to database credentials and environment secrets. This attack allows for persistence and full system compromise, impacting the confidentiality, integrity, and availability of the host application.

## Attack Chain

1. Attacker authenticates to the Lara Dashboard using valid administrative credentials that possess the 'settings.edit' permission.
2. Attacker navigates to the core-upgrades administrative panel within the dashboard interface.
3. Attacker crafts a malicious ZIP archive containing weaponized PHP files designed to overwrite existing application source code.
4. Attacker performs an HTTP POST request to '/admin/settings/core-upgrades/upload' containing the malicious ZIP archive.
5. The application validates the 'settings.edit' permission and proceeds to extract the archive to the web application's root directory.
6. The uploaded malicious PHP files overwrite legitimate application source code, such as 'routes/web.php'.
7. Attacker triggers the execution of the injected code by requesting the modified PHP file via a browser or script.
8. Arbitrary system commands are executed with the privileges of the web server user, resulting in credential exfiltration or full system compromise.

## Impact

Successful exploitation leads to full remote code execution, enabling attackers to extract sensitive environment secrets, access database credentials, and gain persistence on the server. The target is the Lara Dashboard application, specifically affecting installations prior to version 1.3.2.

## Recommendation

Prioritize the upgrade of all Lara Dashboard instances to version 1.3.2 or later to address the insufficient authorization check on the file upload endpoint.
