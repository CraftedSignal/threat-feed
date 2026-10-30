---
brief_id: brief-2026-10-30-phpmyadmin-csrf
event_id: brief-2026-10-30-phpmyadmin-csrf
revision: 1
activity_at: "2026-10-30T13:29:37Z"
title: 'phpMyAdmin: Cross-Site Request Forgery via non-AJAX POST (CVE-2026-119426)'
slug: 2026-10-phpmyadmin-csrf
description: phpMyAdmin versions up to 5.2.3 are susceptible to a CSRF vulnerability allowing remote attackers to execute arbitrary SQL queries by tricking authenticated users into submitting malicious non-AJAX POST requests.
date: "2026-10-30T13:29:37Z"
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
  - cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*
vendors:
  - phpMyAdmin
products:
  - phpMyAdmin (<= 5.2.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can lure authenticated victims into submitting cross-site POSTs.
    confidence_band: high
cves:
  - id: CVE-2026-119426
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119426
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review web server logs for high volumes of POST requests to /sql or /database/sql without corresponding AJAX headers or legitimate referrers.
      owner: SOC
      due: 48h
      evidence: Source notes the vulnerability targets /sql or /database/sql via non-AJAX POST requests.
  hunt_leads:
    - lead: Identify internal users accessing phpMyAdmin and perform baselining of POST requests to database endpoints.
      technique_id: T1566
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source details the exploitation vector via POST requests to specific paths.
  mitigation_plan:
    - priority: immediate
      action: Upgrade phpMyAdmin to the latest secure version once available.
      owner: IT Operations
      addresses: CVE-2026-119426
      evidence: Vulnerability exists through version 5.2.3.
---

phpMyAdmin versions through 5.2.3 are vulnerable to a cross-site request forgery (CSRF) flaw that stems from the improper validation of CSRF tokens during non-AJAX POST requests. When using http or config authentication, an attacker can craft a malicious cross-site POST request targeting the /sql or /database/sql endpoints. If an authenticated user interacts with this request, the attacker can execute arbitrary SQL commands with the victim's database privileges.

## Impact
Successful exploitation allows for the execution of arbitrary SQL commands on the database server using the privileges of the victimized user. This could lead to unauthorized data exposure, modification, or deletion, depending on the victim's database permissions.

## Recommendation
- Upgrade phpMyAdmin to a patched version beyond 5.2.3 as soon as one is released.
- Implement strict SameSite cookie attributes (e.g., SameSite=Strict or SameSite=Lax) on the web server hosting phpMyAdmin to mitigate CSRF risks.
- Advise administrators and users to avoid browsing untrusted websites while authenticated to sensitive database administration interfaces.
- Monitor web access logs for suspicious POST requests to /sql or /database/sql originating from unexpected Referer or Origin headers.
