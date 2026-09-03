---
title: MailPit Denial of Service Vulnerability
slug: 2026-08-mailpit-dos
description: A vulnerability in the MailPit application allows a remote, unauthenticated attacker to trigger a Denial of Service condition, resulting in service unavailability.
date: "2026-08-21T19:14:52Z"
lastmod: "2026-09-03T00:03:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:axllent:mailpit:*:*:*:*:*:*:*:*
vendors:
  - Axllent
products:
  - MailPit (< 1.30.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A remote, unauthenticated attacker can exploit a vulnerability in MailPit to carry out a Denial of Service attack.
    confidence_band: high
cves:
  - id: CVE-2026-67445
    cvss: 5.3
    epss: 0.00371
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2949
  - https://github.com/advisories/GHSA-w878-pj84-3j5v
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict access to MailPit instances to internal/trusted networks via firewall or VPN.
      owner: IT Operations
      due: 24h
      evidence: Mitigate unauthenticated remote access risk.
  mitigation_plan:
    - priority: immediate
      action: Patch MailPit to 1.30.4 or later
      owner: IT Operations
      addresses: MailPit DoS vulnerability
      evidence: BSI security advisory recommendation.
updates:
  - at: "2026-09-03T00:03:12Z"
    level: L2
    summary: added CVE-2026-67445; mailpit version < 1.30.4
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-w878-pj84-3j5v
---

The BSI has released an advisory regarding a Denial of Service (DoS) vulnerability affecting the MailPit application. MailPit, a popular email testing tool, contains a flaw that can be exploited by an unauthenticated, remote attacker to crash the service or render it unresponsive. This vulnerability poses a risk to development and testing environments where MailPit is deployed. Because the exploit can be initiated remotely without authentication, defenders should prioritize patching or restricting access to the MailPit interface to trusted networks to prevent service disruption. No specific CVE identifier was provided in the initial advisory at the time of publication.

## Impact

Successful exploitation of this vulnerability results in a Denial of Service, causing the MailPit application to become unavailable. This impacts development workflows that rely on MailPit for email testing, potentially halting testing cycles and affecting development productivity in impacted organizations.

## Recommendation

- Monitor the official MailPit release channels for updates or patches addressing this DoS vulnerability.
- Restrict network access to the MailPit web interface and SMTP service to authorized subnets only, preventing unauthenticated remote access.
- Review network logs for unusual spikes in traffic directed at MailPit instances that may indicate exploitation attempts.
