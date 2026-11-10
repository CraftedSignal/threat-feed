---
brief_id: brief-2026-11-10-firekylin-auth-bypass
event_id: brief-2026-11-10-firekylin-auth-bypass
revision: 1
activity_at: "2026-11-10T18:27:48Z"
title: 'Firekylin: Improper authorization vulnerability (CVE-2026-125750)'
slug: 2026-11-firekylin-auth-bypass
description: Firekylin versions 2.18.1 and earlier contain an improper authorization flaw in the admin API that allows editor-role users to access sensitive administrative secrets and perform unauthorized actions.
date: "2026-11-10T18:27:48Z"
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
cpes:
  - cpe:2.3:a:firekylin:firekylin:*:*:*:*:*:*:*:*
vendors:
  - Firekylin
products:
  - Firekylin (<= 2.18.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Editors can query ... user.js for other users app_key/app_secret to publish posts as administrators via admin/post_push.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: The admin API base guard permits all GET actions... to retrieve TOTP secrets, push credentials, and cloud storage keys.
    confidence_band: high
cves:
  - id: CVE-2026-125750
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125750
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Audit web server access logs for requests to /api/admin/options.js and /api/admin/user.js originating from users with the editor role.
      owner: SOC
      due: 24h
      evidence: The admin API base guard permits all GET actions... Editors can query options.js for TOTP secrets... or user.js.
  hunt_leads:
    - lead: Identify unauthorized access to administrative API endpoints by non-administrator users.
      technique_id: T1068
      data_needed:
        - Web server access logs
        - Application level authorization logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The admin API base guard permits all GET actions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Firekylin to a patched version beyond 2.18.1.
      owner: IT Operations
      addresses: CVE-2026-125750
      evidence: Firekylin through 2.18.1 contains an improper authorization vulnerability
---

Firekylin versions 2.18.1 and earlier contain an improper authorization vulnerability in the admin API base guard. The vulnerability exists because the guard mechanism fails to restrict GET requests for administrative endpoints. An attacker authenticated with 'editor' privileges can perform unauthorized queries against the 'options.js' and 'user.js' endpoints to retrieve sensitive data, including TOTP secrets, push credentials, and cloud storage keys. Furthermore, attackers can exploit this access to retrieve user API keys ('app_key'/'app_secret'), enabling them to publish content as administrators via the 'admin/post_push' endpoint.

## Impact

The impact of this vulnerability includes the unauthorized disclosure of sensitive system configuration and administrative credentials, and the potential for account takeover or unauthorized content publication.

## Recommendation

- Identify all instances of Firekylin in the environment.
- Review access logs for 'editor'-role users accessing 'options.js', 'user.js', or 'admin/post_push' endpoints.
- Upgrade Firekylin to a version beyond 2.18.1 immediately upon vendor patch release.
