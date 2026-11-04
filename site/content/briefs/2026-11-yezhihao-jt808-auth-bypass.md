---
brief_id: brief-2026-11-04-yezhihao-jt808-auth-bypass
event_id: brief-2026-11-04-yezhihao-jt808-auth-bypass
revision: 1
activity_at: "2026-11-04T18:51:14Z"
title: 'yezhihao jt808-server: Web Management API authentication bypass (CVE-2026-121926)'
slug: 2026-11-yezhihao-jt808-auth-bypass
description: A missing authentication vulnerability in the jt808-server Web Management API allows remote attackers to bypass security controls via the WebMvcConfig.addInterceptors function.
date: "2026-11-04T18:51:14Z"
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
  - cpe:2.3:a:yezhihao:jt808_server:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-application
  - cve-2026-121926
vendors:
  - yezhihao
products:
  - jt808-server (<= a07f68c466b560b97ef41edb8a4966469abdf83e)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation results in missing authentication. The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-121926
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121926
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the jt808-server Web Management API to authorized management subnets.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows remote unauthenticated access.
  hunt_leads:
    - lead: Identify unauthenticated requests to the Web Management API endpoints.
      technique_id: T1190
      data_needed:
        - Web server access logs (HTTP request method, URI path, source IP, response status code)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The flaw exists in the Web Management API component.
  mitigation_plan:
    - priority: immediate
      action: Isolate or block network access to the affected service until the vendor provides a patch.
      owner: IT Operations
      addresses: CVE-2026-121926
      evidence: Product maintains a rolling release and lacks specific version identifiers for updates.
---

A missing authentication vulnerability exists in the Web Management API of the yezhihao jt808-server, specifically within the WebMvcConfig.addInterceptors function. The flaw allows remote, unauthenticated attackers to gain unauthorized access to the application's management interface. This vulnerability affects all versions of the product up to commit hash a07f68c466b560b97ef41edb8a4966469abdf83e. As the software is distributed via a rolling release model, there are no specific version numbers for patches or affected builds. The vendor has not responded to disclosure attempts.

## Impact
Successful exploitation enables remote, unauthenticated access to the Web Management API, which may lead to unauthorized system configuration changes or data exposure within the jt808-server environment.

## Recommendation
- Inventory all instances of jt808-server within your environment.
- Restrict access to the Web Management API at the network level using firewalls or VPNs until the vendor provides a remediation or the source code is patched manually.
- Monitor web server logs for suspicious, unauthenticated access attempts targeting API endpoints, particularly those associated with administrative functions.
