---
brief_id: brief-2026-11-12-asiainfo-bss-vulns
event_id: brief-2026-11-12-asiainfo-bss-vulns
revision: 1
activity_at: "2026-11-12T14:03:36Z"
title: AsiaInfo Business Support System (BSS) multiple vulnerabilities (CVE-2026-125297, CVE-2026-125298)
slug: 2026-11-asiainfo-bss-vulns
description: AsiaInfo Business Support System (BSS) contains critical vulnerabilities including missing authentication and improper JWT signature verification, allowing remote unauthenticated attackers to hijack accounts and execute administrative actions.
date: "2026-11-12T14:03:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
vendors:
  - AsiaInfo
products:
  - Business Support System (BSS) (9.2.0 - 9.2.40)
  - aether-menu (< 2.2.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote, unauthenticated attacker could provision a new account with administrative privileges or take over existing accounts.
    confidence_band: high
cves:
  - id: CVE-2026-125297
    cvss: 9.8
    epss: 0.00772
    kev_status: "false"
  - id: CVE-2026-125298
    cvss: 9.8
    epss: 0.00535
    kev_status: "false"
references:
  - https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-313-03.json
rules:
  - title: Detect CVE-2026-125297 Exploitation - Unauthorized Access to BSS API
    description: Detects unauthenticated requests to the management API /bss/sysmgnt/api/ which is vulnerable to missing authentication per CVE-2026-125297.
    platform: sigma
    severity: high
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
    - action: Upgrade AsiaInfo BSS to version 9.2.41 and aether-menu to 2.2.7
      owner: IT Operations
      due: 48h
      evidence: 'Remediation: Fixed in 9.2.41.'
  hunt_leads:
    - lead: Identify successful logins or administrative account creation requests originating from unknown or non-administrative IP addresses targeting the /bss/sysmgnt/api/ endpoint.
      technique_id: T1190
      data_needed:
        - Web server access logs
        - Application audit logs for BSS
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: A remote, unauthenticated attacker could provision a new account with administrative privileges or take over existing accounts.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to AsiaInfo BSS version 9.2.41
      owner: IT Operations
      addresses: CVE-2026-125297, CVE-2026-125298
      evidence: Fixed in 9.2.41.
---

AsiaInfo Business Support System (BSS) versions 9.2.0 through 9.2.40 contain critical vulnerabilities that enable unauthenticated remote attackers to bypass authentication mechanisms and execute administrative actions. The vulnerabilities include missing authentication for the management API and failure to verify cryptographic signatures for JSON Web Tokens (JWT). These flaws allow attackers to provision new administrative accounts or take over existing ones. These issues are addressed in BSS version 9.2.41 and aether-menu version 2.2.7.

## Impact
Successful exploitation allows remote, unauthenticated attackers to gain unauthorized administrative access to the BSS platform, potentially leading to full system compromise, account takeover, and unauthorized administrative configuration changes.

## Recommendation
- Upgrade AsiaInfo Business Support System (BSS) to version 9.2.41 or later immediately.
- Ensure the updated aether-menu version 2.2.7 is deployed with the BSS update.
- Audit existing user accounts and API configurations within BSS for unauthorized changes created prior to the update.
- Implement strict network access controls to limit exposure of the /bss/sysmgnt/api/ endpoint to only trusted administrative workstations.
