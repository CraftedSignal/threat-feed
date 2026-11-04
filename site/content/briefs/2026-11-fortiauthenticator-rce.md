---
brief_id: brief-2026-11-04-fortiauthenticator-rce
event_id: brief-2026-11-04-fortiauthenticator-rce
revision: 1
activity_at: "2026-11-04T02:48:41Z"
title: 'Fortinet FortiAuthenticator: Unauthenticated remote code execution (CVE-2026-44277)'
slug: 2026-11-fortiauthenticator-rce
description: A critical unauthenticated remote code execution vulnerability (CVE-2026-44277) in FortiAuthenticator caused by improper access control on API endpoints now has public proof-of-concept exploit code available.
date: "2026-11-04T02:48:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "3"
  rating: B3
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Awaiting environment validation for API logging visibility
cpes:
  - cpe:2.3:a:fortinet:fortiauthenticator:*:*:*:*:*:*:*:*
tags:
  - rce
  - vulnerability
  - api-security
vendors:
  - Fortinet
products:
  - FortiAuthenticator (<= 6.4.10, 6.5.0-6.5.6, 6.6.0-6.6.8, 8.0.0-8.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated RCE in Fortinet FortiAuthenticator via improper access control on API endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-44277
    cvss: 9.8
    epss: 0.00551
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-44277
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XBLACKASH-CVE-2026-44277&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-44277 Exploitation - Unauthenticated RCE via API
    description: Detects potential exploitation of CVE-2026-44277 by monitoring for unauthorized access to the FortiAuthenticator API endpoint /api/v1/aaa
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
    - IT Operations
  immediate_actions:
    - action: Patch FortiAuthenticator to version 6.5.7, 6.6.9, or 8.0.3
      owner: IT Operations
      due: 24h
      evidence: Source specifies these versions as the fixed versions
    - action: Implement IP allowlisting for the management interface
      owner: IT Operations
      due: 24h
      evidence: Mitigation recommendation provided by source
  hunt_leads:
    - lead: Identify unauthorized access attempts to /api/v1/aaa
      technique_id: T1190
      data_needed:
        - Web application access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit code attempts to interact with /api/v1/aaa
  mitigation_plan:
    - priority: immediate
      action: Upgrade to fixed versions
      owner: IT Operations
      addresses: CVE-2026-44277
      evidence: Source provides fixed versions for each product branch
---

CVE-2026-44277 is a critical remote code execution vulnerability in Fortinet FortiAuthenticator. The flaw exists due to improper access control on specific API endpoints, which allows unauthenticated attackers to execute arbitrary code on the appliance. Proof-of-concept exploit code has been publicly released, increasing the risk of exploitation. FortiAuthenticator Cloud is not affected.

## Impact

Successful exploitation allows an unauthenticated attacker to gain full control of the FortiAuthenticator appliance. This facilitates further malicious activity, such as lateral movement into integrated Active Directory or RADIUS environments.

## Recommendation

- Upgrade to a patched version immediately: FortiAuthenticator 6.5.7 or later, 6.6.9 or later, or 8.0.3 or later.
- Restrict access to the FortiAuthenticator administration interface by requiring VPN access and implementing IP allowlisting.
- Disable all unnecessary API access until patching is complete.
