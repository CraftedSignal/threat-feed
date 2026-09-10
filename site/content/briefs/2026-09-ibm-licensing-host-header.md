---
title: Host Header Injection in IBM Common Licensing Agent and ART
slug: 2026-09-ibm-licensing-host-header
description: IBM Common Licensing Agent and ART versions 9.0 through 9.0.0.2 are vulnerable to an unauthenticated remote redirect attack via improper HTTP Host header validation.
date: "2026-09-10T23:09:42Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - IBM
products:
  - Common Licensing Agent (9.0, 9.0.0.1, 9.0.0.2)
  - Common Licensing ART (9.0, 9.0.0.1, 9.0.0.2)
cves:
  - id: CVE-2026-19646
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19646
rules:
  - title: Detect CVE-2026-19646 Exploitation - Host Header Injection
    description: Detects HTTP requests targeting IBM Licensing services where the Host header does not match authorized internal domains, indicating potential injection attempts.
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
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade affected IBM Common Licensing Agent and ART products
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-19646 vulnerability disclosure
  hunt_leads:
    - lead: Search web logs for outgoing redirects to suspicious external domains from licensing application endpoints
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source confirms potential for arbitrary domain redirection
  mitigation_plan:
    - priority: immediate
      action: Implement Host header validation at the reverse proxy
      owner: IT Operations
      addresses: CVE-2026-19646
      evidence: Source identifies Host header validation failure
---

IBM Common Licensing Agent and IBM Common Licensing ART versions 9.0, 9.0.0.1, and 9.0.0.2 contain a critical vulnerability, tracked as CVE-2026-19646, resulting from the improper validation of the HTTP Host header. This flaw allows a remote, unauthenticated attacker to manipulate the Host header in incoming HTTP requests to force the application to redirect users to an arbitrary, attacker-controlled domain. This vulnerability facilitates phishing campaigns, credential harvesting, and the delivery of malicious content by abusing the trust associated with the targeted licensing infrastructure. With a CVSS base score of 9.1, this vulnerability poses a significant risk to organizations relying on these products for license management.

## Impact

Successful exploitation allows attackers to perform open redirects through the licensing application. This can be weaponized to bypass security controls, trick users into visiting malicious websites, or conduct targeted social engineering attacks, potentially leading to widespread internal credential theft or compromise of administrative sessions within the corporate environment.

## Recommendation

Prioritize the remediation of all affected IBM Common Licensing Agent and ART instances. Monitor web server logs for suspicious requests containing modified Host headers that deviate from expected internal hostnames.

- Upgrade all instances of IBM Common Licensing Agent and ART to the latest patched version provided by IBM.
- Implement strict HTTP Host header validation on load balancers or reverse proxies sitting in front of these services to reject requests with unexpected Host values.
- Audit webserver access logs for anomalous redirects occurring from the licensing application paths to external domains.
