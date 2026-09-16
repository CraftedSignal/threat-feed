---
title: 'CVE-2026-92751: CSRF Vulnerability in CMAK Allows Unauthenticated State Changes'
slug: 2026-09-cmak-csrf
description: CMAK versions up to 3.0.0.6 are vulnerable to Cross-Site Request Forgery (CSRF) due to missing request filters, enabling attackers to execute unauthorized actions like cluster deletion or configuration changes.
date: "2026-09-16T23:51:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:cmak_project:cmak:*:*:*:*:*:*:*:*
vendors:
  - CMAK
products:
  - CMAK (<= 3.0.0.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker can trick an authenticated operator into submitting malicious requests by leveraging existing HTTP Basic authentication or cookies.
    confidence_band: med
cves:
  - id: CVE-2026-92751
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92751
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade CMAK to a patched version beyond 3.0.0.6
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-92751 vulnerability description
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the CMAK web interface to trusted management networks
      owner: IT Operations
      addresses: CVE-2026-92751
      evidence: Source documentation of CSRF vulnerability
---

CMAK (formerly Kafka Manager) versions 3.0.0.6 and earlier are susceptible to a Cross-Site Request Forgery (CSRF) vulnerability. The application fails to implement a CSRF filter, permitting an attacker to perform state-changing operations on behalf of an authenticated operator. The vulnerability persists because the application utilizes HTTP Basic authentication and session cookies that lack proper 'SameSite' attribute protections. An attacker can entice an authenticated administrator to visit a malicious site containing a hidden form, which subsequently submits unauthorized requests to sensitive endpoints within the CMAK interface, such as those responsible for deleting Kafka topics or modifying cluster configurations. This vulnerability poses a significant risk to the integrity and availability of managed Kafka clusters.

## Impact

Successful exploitation allows an unauthenticated attacker to perform destructive administrative actions on managed Kafka clusters, including topic deletion and cluster configuration modification, leading to service disruption or unauthorized data manipulation.

## Recommendation

* Prioritize upgrading CMAK to a version beyond 3.0.0.6 that includes CSRF protections.
* Implement restrictive CORS and SameSite cookie policies at the web server or reverse proxy level if immediate application patching is not feasible.
* Ensure that any administrative interfaces managing Kafka clusters are not exposed to the public internet and require additional layers of authentication or VPN access.
