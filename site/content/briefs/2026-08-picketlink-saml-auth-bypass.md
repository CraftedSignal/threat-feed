---
title: PicketLink Federation SAML Authentication Bypass via Forged Assertions
slug: 2026-08-picketlink-saml-auth-bypass
description: A vulnerability in the PicketLink Federation SAML unsolicited response handler allows unauthenticated attackers to forge assertions, resulting in full authentication bypass as any principal.
date: "2026-08-11T09:39:28Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - saml
  - picketlink
  - vulnerability
vendors:
  - Red Hat
products:
  - PicketLink Federation
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The unsolcited response handler would accept forged assertions with no verification or validation, permitting an unauthed attacker to authenticate as any principal in any role.
    confidence_band: high
cves:
  - id: CVE-2026-10579
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-10579
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch affected PicketLink Federation instances per Red Hat security advisory.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-10579 vulnerability disclosure.
  hunt_leads:
    - lead: Audit access logs for accounts demonstrating administrative behavior without prior SSO session authentication.
      technique_id: T1550.001
      data_needed:
        - Application authentication logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated actors to bypass authentication flows.
---

CVE-2026-10579 describes a critical authentication bypass vulnerability identified in the PicketLink Federation SAML component. The vulnerability exists within the unsolicited response handler, which fails to perform necessary cryptographic verification or structural validation of incoming SAML assertions. An attacker can craft a malicious, forged SAML assertion to impersonate any user within the target system, including users with administrative roles. Because the service does not validate the integrity or the origin of the unsolicited SAML response, the application incorrectly trusts the forged identity claims. This flaw exposes affected systems to unauthorized information access, the performance of sensitive operations on behalf of other users, and full account takeover. The impact is significant, warranting immediate investigation into implementations using PicketLink for SAML-based authentication.

## Impact

Successful exploitation allows unauthenticated attackers to assume the identity of any principal, including highly privileged administrative accounts. This leads to complete compromise of confidentiality, integrity, and availability within the target application. Potential damage includes unauthorized exfiltration of sensitive organizational data, modification of application state, and execution of restricted administrative functions, effectively negating the organization's authentication perimeter.

## Recommendation

- Identify all instances of PicketLink Federation within the enterprise environment and verify the version in use.
- Apply security patches provided by Red Hat as soon as they become available.
- Monitor authentication logs for anomalous SAML assertion patterns, specifically identifying unsolicited responses from unexpected or non-standard Identity Providers.
- Review application access logs for account changes or administrative actions initiated by accounts that lack corresponding successful login sessions in external IdP logs.
