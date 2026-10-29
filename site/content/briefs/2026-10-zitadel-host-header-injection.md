---
brief_id: brief-2026-10-29-zitadel-host-header-injection
event_id: brief-2026-10-29-zitadel-host-header-injection
revision: 1
activity_at: "2026-10-29T17:33:26Z"
title: 'ZITADEL: Login V2 UI host header injection (CVE-2026-119127)'
slug: 2026-10-zitadel-host-header-injection
description: ZITADEL versions 4.0.0 before 4.19.5 are vulnerable to host header injection, allowing unauthenticated attackers to redirect sensitive authentication-related emails to attacker-controlled infrastructure.
date: "2026-10-29T17:33:26Z"
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
  validation_status: Source-confirmed vulnerability; environment verification of header-injection susceptibility required.
cpes:
  - cpe:2.3:a:zitadel:zitadel:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - host-header-injection
  - cve-2026-119127
vendors:
  - ZITADEL
products:
  - ZITADEL (< 4.19.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    subtechnique_id: T1566.002
    subtechnique_name: Spearphishing Link
    evidence: Attackers knowing a victim's login name can point the links in genuine emails at their host, harvest the single-use codes when the links are opened, and take over accounts including instance administrators.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1199
    technique_name: Trusted Relationship
    evidence: Attackers knowing a victim's login name can point the links in genuine emails at their host, harvest the single-use codes when the links are opened, and take over accounts including instance administrators.
    confidence_band: high
cves:
  - id: CVE-2026-119127
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119127
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ZITADEL to 4.19.5 or later
      owner: IT Operations
      due: 24h
      evidence: ZITADEL 4.0.0 before 4.19.5 contains a host header injection vulnerability.
  hunt_leads:
    - lead: Identify HTTP requests to the Login V2 UI containing X-Zitadel-Forward-Host or X-Zitadel-Public-Host headers
      technique_id: T1190
      data_needed:
        - Web server access logs or proxy logs (e.g., Nginx, Envoy, Cloud-native ingress logs)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: By manipulating HTTP headers such as 'x-zitadel-public-host', 'x-zitadel-forward-host', or 'x-forwarded-host', an unauthenticated attacker can influence the destination of sensitive system-generated emails.
  mitigation_plan:
    - priority: immediate
      action: Apply ZITADEL version 4.19.5
      owner: IT Operations
      addresses: CVE-2026-119127
      evidence: ZITADEL 4.0.0 before 4.19.5 contains a host header injection vulnerability.
---

ZITADEL versions 4.0.0 through 4.19.4 are vulnerable to host header injection within the Login V2 UI. An unauthenticated attacker can manipulate the host of generated URLs in password-reset, invite, and email-verification messages by injecting specific headers, including x-zitadel-public-host, x-zitadel-forward-host, and x-forwarded-host. By successfully influencing these links, an attacker can capture single-use authentication tokens when victims click them, facilitating account takeover for users and instance administrators.

## Impact
Successful exploitation allows unauthenticated attackers to perform account takeovers, including high-privileged administrator accounts, by intercepting and harvesting sensitive authentication tokens sent via email.

## Recommendation
- Upgrade ZITADEL instances to version 4.19.5 or later immediately.
- Audit logs for web requests containing unexpected or anomalous X-Forwarded-Host or X-Zitadel-prefixed headers targeting the Login V2 UI.
- Review administrative access logs for suspicious modifications or account lifecycle events during the vulnerability window.
