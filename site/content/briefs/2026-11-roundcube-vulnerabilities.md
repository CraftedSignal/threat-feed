---
brief_id: brief-2026-11-10-roundcube-vulnerabilities
event_id: brief-2026-11-10-roundcube-vulnerabilities
revision: 1
activity_at: "2026-11-10T16:33:17Z"
title: 'Roundcube Webmail: Multiple vulnerabilities'
slug: 2026-11-roundcube-vulnerabilities
description: Multiple vulnerabilities in Roundcube Webmail versions 1.6.x and 1.7.x enable remote attackers to perform arbitrary code execution, SSRF, CSRF, and denial of service.
date: "2026-11-10T16:33:17Z"
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
vendors:
  - Roundcube
products:
  - Roundcube Webmail (< 1.6.21)
  - Roundcube Webmail (< 1.7.6)
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1489/
  - https://roundcube.net/news/2026/11/09/security-updates-1.6.21-and-1.7.6
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Roundcube Webmail to 1.6.21 or 1.7.6
      owner: IT Operations
      due: 24h
      evidence: Roundcube security-updates-1.6.21-and-1.7.6
  hunt_leads:
    - lead: Hunt for anomalous outbound connections originating from the web server hosting Roundcube, potentially indicating SSRF exploitation.
      data_needed:
        - Firewall or Netflow logs
        - Web server egress telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability notice specifies SSRF as a potential impact.
  mitigation_plan:
    - priority: immediate
      action: Patch Roundcube Webmail to versions 1.6.21 or 1.7.6
      owner: IT Operations
      addresses: Multiple vulnerabilities including RCE, SSRF, CSRF, and DoS
      evidence: Roundcube security-updates-1.6.21-and-1.7.6
---

Multiple vulnerabilities have been identified in Roundcube Webmail, affecting versions 1.6.x prior to 1.6.21 and 1.7.x prior to 1.7.6. These vulnerabilities can allow a remote attacker to achieve arbitrary code execution, conduct Server-Side Request Forgery (SSRF), perform Cross-Site Request Forgery (CSRF), and trigger denial-of-service conditions. Security updates have been released by the vendor.

## Recommendation

- Upgrade Roundcube Webmail to version 1.6.21 or 1.7.6 immediately to mitigate the identified security risks.
- Review web server access logs for anomalous POST requests or unexpected outbound connections from the web server host, which may indicate attempted exploitation of SSRF or RCE vulnerabilities.
