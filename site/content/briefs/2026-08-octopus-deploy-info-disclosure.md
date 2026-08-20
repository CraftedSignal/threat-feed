---
title: Information Disclosure Vulnerability in Octopus Deploy Server
slug: 2026-08-octopus-deploy-info-disclosure
description: An authenticated remote attacker can exploit a vulnerability in Octopus Deploy Server to perform unauthorized information disclosure.
date: "2026-08-20T13:11:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - information-disclosure
vendors:
  - Octopus Deploy
products:
  - Octopus Deploy Server
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An authenticated attacker can exploit a vulnerability in Octopus Deploy Server to perform an information disclosure attack.
    confidence_band: high
cves:
  - id: CVE-2024-5175
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2928
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-5175
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch Octopus Deploy Server to remediate CVE-2024-5175
      owner: IT Operations
      due: 72h
      evidence: Vendor vulnerability disclosure
  hunt_leads:
    - lead: Anomalous API calls or UI requests resulting in large data dumps or access to sensitive configuration pages
      technique_id: T1592
      data_needed:
        - Web server logs
        - Application audit logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Information disclosure impact
  mitigation_plan:
    - priority: immediate
      action: Review and restrict user permissions within Octopus Deploy
      owner: IT Operations
      addresses: CVE-2024-5175
      evidence: Vulnerability requires authentication
---

Octopus Deploy has disclosed a vulnerability in Octopus Deploy Server that allows an authenticated, remote attacker to gain access to sensitive information. The flaw, identified as CVE-2024-5175, involves improper handling of data within the application. Because the vulnerability requires prior authentication, it poses a significant risk to organizations where users have varied permission levels, potentially allowing internal actors or compromised accounts to elevate their visibility into sensitive deployment configurations, variables, or credentials. Defenders should focus on reviewing access logs for anomalous data access patterns and ensuring that all instances of Octopus Deploy Server are updated to a non-vulnerable version immediately.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive information managed by the Octopus Deploy platform. This may include environment variables, API keys, or deployment package configurations, which can be further leveraged to facilitate lateral movement or secondary attacks within the CI/CD pipeline.

## Recommendation

* Upgrade Octopus Deploy Server instances to the latest version as recommended by the vendor.
* Review administrative and user access logs to identify unusual patterns of data access or configuration retrieval that deviate from standard deployment workflows.
* Implement the principle of least privilege for all user accounts accessing the Octopus Deploy dashboard.
