---
brief_id: brief-2026-11-07-transliterator-sqli
event_id: brief-2026-11-07-transliterator-sqli
revision: 1
activity_at: "2026-11-07T14:08:26Z"
title: 'Transliterator WordPress plugin: Unauthenticated SQL injection (CVE-2026-39732)'
slug: 2026-11-transliterator-sqli
description: An unauthenticated SQL injection vulnerability in the Transliterator WordPress plugin allows attackers to extract arbitrary database content via the name query parameter using double percent-encoded payloads.
date: "2026-11-07T14:08:26Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: very likely
qa_status:
  verdict: pass
products:
  - Transliterator (serbian-transliteration)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated SQL injection in Transliterator WordPress plugin reads arbitrary database contents.
    confidence_band: high
cves:
  - id: CVE-2026-39732
    cvss: 9.3
    epss: 0.00323
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=3C104BE6-16B8-5B6A-A4CA-1441E8DBD227
  - https://vulners.com/cve/CVE-2026-39732
  - https://sploitus.com/exploit?id=3C104BE6-16B8-5B6A-A4CA-1441E8DBD227&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-39732 Exploitation - SQL Injection in Transliterator
    description: Detects exploitation attempts against CVE-2026-39732 using double percent-encoded single quotes in the name query parameter.
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
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Disable Transliterator plugin across all WordPress instances
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-39732 is a high severity SQLi with public exploit code
  hunt_leads:
    - lead: Identify anomalies in request frequency to the name parameter that may indicate automated blind SQLi
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: PoC uses a script to automate boolean blind reader
  mitigation_plan:
    - priority: immediate
      action: Deactivate the affected plugin
      owner: IT Operations
      addresses: CVE-2026-39732
      evidence: Disabling the plugin removes the vulnerable code path
---

The Transliterator WordPress plugin is vulnerable to unauthenticated SQL injection (CVE-2026-39732) due to insufficient input filtering on the 'name' query variable. Attackers can bypass input constraints by using double percent-encoded single quotes ('%2527'), which allows for boolean-based and time-based blind SQL injection. The vulnerability is present by default as the 'permalink-transliteration' feature is enabled in default installations. A publicly available proof-of-concept exploit is circulating.

## Attack Chain
1. Attacker identifies a WordPress site with the Transliterator plugin enabled.
2. Attacker crafts a malicious GET request containing a double percent-encoded payload in the 'name' query parameter.
3. The plugin fails to sanitize the input, allowing the payload to break out of the SQL string literal.
4. Attacker performs boolean-based blind SQL injection to infer database contents based on HTTP 200 (TRUE) or HTTP 404 (FALSE) responses.
5. Attacker performs time-based blind SQL injection to confirm data extraction.
6. Attacker iteratively exfiltrates database content, such as 'wp_options' table data including sensitive configuration.

## Recommendation
- Immediately disable the Transliterator plugin on all WordPress sites until a patch is verified and applied.
- Review web server access logs for requests containing the '%2527' string pattern or repeated requests to the same URL structure with varying boolean-based SQL query parameters.
- Audit WordPress database logs or access logs for high-frequency automated requests originating from unknown IPs targeting the 'name' query variable.
