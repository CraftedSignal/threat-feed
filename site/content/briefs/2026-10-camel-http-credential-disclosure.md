---
title: Credential Disclosure in Apache Camel camel-http Component
slug: 2026-10-camel-http-credential-disclosure
description: CVE-2026-85251 allows for unauthorized credential exposure when the camel-http component follows HTTP redirects to attacker-controlled hosts.
date: "2026-10-19T19:23:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - camel-http
  - credential-disclosure
  - apache
vendors:
  - Apache
products:
  - camel-http (4.0.0-4.18.4, 4.19.0-4.22.0)
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: A remote endpoint — or anyone who can influence its responses — could collect the bearer token or configured credentials simply by answering with a redirect to a host it controls.
    confidence_band: high
cves:
  - id: CVE-2026-85251
    cvss: 7.5
references:
  - https://camel.apache.org/security/CVE-2026-85251.html
  - https://issues.apache.org/jira/browse/CAMEL-24452
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Apache Camel to 4.18.5, 4.22.1, or 4.23.0
      owner: IT Operations
      due: 48h
      evidence: Fixed versions 4.18.5, 4.22.1, 4.23.0
  mitigation_plan:
    - priority: immediate
      action: Disable followRedirects on Camel HTTP endpoints
      owner: IT Operations
      addresses: CVE-2026-85251
      evidence: 'Mitigation if you cannot upgrade: Set followRedirects=false'
---

Apache Camel's 'camel-http' component is vulnerable to a credential disclosure vulnerability (CVE-2026-85251), allowing sensitive authentication headers to be leaked during HTTP redirects. When the 'followRedirects' configuration is enabled, the component incorrectly re-attaches 'Authorization' headers - including OAuth2 bearer tokens or basic/digest credentials - to any host specified in a 'Location' redirect header. 

This vulnerability stems from the 'OAuth2ClientConfigurer' and 'DefaultAuthenticationHttpClientConfigurer' logic, which fails to scope credentials to the intended target authority. Consequently, a remote endpoint can force the client to disclose credentials by providing a 302 redirect to an attacker-controlled server. This flaw primarily affects Spring Boot implementations where 'camel-http' is utilized. The issue was disclosed and assigned a CVSS score of 7.5 (High). Users are advised to upgrade to the fixed versions (4.18.5, 4.22.1, or 4.23.0) or disable automatic redirection as a temporary mitigation.

## Impact

Successful exploitation leads to the exposure of sensitive OAuth2 bearer tokens, basic authentication credentials, or digest authentication credentials to unauthorized third parties. This allows an attacker to collect valid credentials and subsequently impersonate the authenticated client to access protected resources, potentially leading to unauthorized data exfiltration or system compromise within the affected organization's internal infrastructure.

## Recommendation

* Prioritize upgrading 'camel-http' to versions 4.18.5, 4.22.1, or 4.23.0 to include the scoping fixes for 'OAuth2ClientConfigurer' and 'DefaultAuthenticationHttpClientConfigurer'.
* If patching is not immediately feasible, modify application code to disable 'followRedirects' on any Camel route endpoints that carry credentials.
* Implement explicit redirect handling within Camel routes to ensure that redirect destinations are strictly controlled and validated against an allowlist of trusted hosts.
