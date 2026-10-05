---
title: Authentication Bypass Vulnerability in Casdoor
slug: 2026-10-casdoor-auth-bypass
description: A missing authentication vulnerability in Casdoor versions up to 3.161.1 allows remote attackers to bypass security controls via the ApiFilter function.
date: "2026-10-05T14:40:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:casdoor:casdoor:*:*:*:*:*:*:*:*
vendors:
  - Casdoor
products:
  - Casdoor (<= 3.161.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105307
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105307
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict access to Casdoor API endpoints at the network perimeter
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthenticated remote access to API endpoints
  mitigation_plan:
    - priority: immediate
      action: Apply network-level filtering to block unauthorized access to API routers
      owner: IT Operations
      addresses: CVE-2026-105307
      evidence: Vulnerability originates in routers/authz_filter.go
  gaps:
    - Lack of official vendor patch
---

Casdoor versions up to and including 3.161.1 contain a critical security vulnerability in the ApiFilter function within the file routers/authz_filter.go. This component, which governs authorization logic for API endpoints, fails to properly enforce authentication, allowing unauthenticated remote attackers to interact with protected resources. The vulnerability is categorized as a missing authentication flaw, which can be exploited remotely without requiring valid credentials. Because the exploit mechanism is public and the vendor has not provided a response or patch, instances of Casdoor are at an elevated risk of unauthorized access and potential data exposure. Organizations running Casdoor should evaluate their exposure and implement compensating controls, such as limiting access to the API surface at the network edge.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to bypass authentication controls, effectively granting them unauthorized access to sensitive application data and API functionality. Given the core role of Casdoor as an identity and access management system, this impact is severe and could facilitate lateral movement or data exfiltration across connected services.

## Recommendation

- Implement network-level restrictions using a Web Application Firewall (WAF) or reverse proxy to block unauthenticated requests to the API endpoints managed by Casdoor until a security patch is available.
- Audit access logs for anomalous requests to API paths, particularly those that bypass standard authentication flows, to identify potential exploitation attempts.
- Review the deployment environment for Casdoor to ensure it is not exposed to the public internet unless absolutely necessary.
- Monitor the vendor repository for the release of an official security patch for versions 3.161.1 and earlier.
