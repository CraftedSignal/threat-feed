---
title: Authentication Bypass Vulnerability in IBM Security Verify Access and Identity Access
slug: 2026-10-ibm-auth-bypass
description: IBM Security Verify Access and Identity Access contain an improper authentication vulnerability (CVE-2026-16823) allowing unauthenticated remote attackers to bypass security restrictions.
date: "2026-10-08T22:04:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ibm:security_verify_access:*:*:*:*:*:*:*:*
  - cpe:2.3:a:ibm:verify_identity_access:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve
  - identity-management
vendors:
  - IBM
products:
  - Security Verify Access (10.0-10.0.9.2)
  - Verify Identity Access (11.0-11.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: The vulnerability allows a remote attacker to bypass security restrictions due to improper authentication.
    confidence_band: high
cves:
  - id: CVE-2026-16823
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16823
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch IBM Security Verify Access to the version remediating CVE-2026-16823.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-16823
    - action: Monitor authentication logs for unauthorized successful logins on IBM platforms.
      owner: SOC
      due: 24h
      evidence: CVE-2026-16823
  mitigation_plan:
    - priority: immediate
      action: Update affected IBM software versions.
      owner: IT Operations
      addresses: CVE-2026-16823
      evidence: CVE-2026-16823
---

IBM Security Verify Access (versions 10.0 through 10.0.9.2) and IBM Verify Identity Access (versions 11.0 through 11.0.3) are affected by a critical vulnerability, tracked as CVE-2026-16823, which stems from improper authentication. This flaw permits a remote, unauthenticated attacker to bypass established security restrictions. With a CVSS v3.1 base score of 9.1, this vulnerability poses a significant risk to the integrity and confidentiality of identity and access management environments. Defenders should prioritize patching, as successful exploitation enables unauthorized access to systems protected by these IBM platforms without the need for valid credentials.

## Impact

Successful exploitation of CVE-2026-16823 allows remote attackers to circumvent authentication mechanisms. This facilitates unauthorized access to sensitive corporate resources, identity stores, and administrative interfaces managed by IBM Security Verify Access or Identity Access. Given the nature of these products as centralized access controllers, the impact includes potential full compromise of protected downstream applications and data exfiltration.

## Recommendation

* Apply the security patches provided by IBM for Security Verify Access and Verify Identity Access to resolve CVE-2026-16823.
* Monitor webserver and authentication logs for anomalous access patterns or unexpected authentication success events originating from unknown or external IP addresses targeting the Verify Access management interfaces.
* Review administrative logs for unauthorized activity occurring immediately following a bypass attempt.
