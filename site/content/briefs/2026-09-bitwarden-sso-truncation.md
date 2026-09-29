---
title: Authentication Bypass in Bitwarden Server via SSO Identifier Truncation
slug: 2026-09-bitwarden-sso-truncation
description: A SQL Server stored procedure parameter truncation vulnerability (CVE-2026-101878) in Bitwarden Server allows attackers to authenticate as other users by crafting overlapping SSO identifiers.
date: "2026-09-29T02:24:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:bitwarden:server:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - cve-2026-101878
  - identity-management
vendors:
  - Bitwarden
products:
  - Bitwarden Server (< 2026.5.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The truncation of the @ExternalId parameter allows a user to authenticate as that member and obtain a victim-scoped access token.
    confidence_band: high
cves:
  - id: CVE-2026-101878
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101878
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Bitwarden Server to 2026.5.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source identifies 2026.5.0 as the version resolving the truncation issue
  mitigation_plan:
    - priority: immediate
      action: Upgrade Bitwarden Server to 2026.5.0
      owner: IT Operations
      addresses: CVE-2026-101878
      evidence: Source specifies the affected version range
---

Bitwarden Server versions 2025.6.0 through versions prior to 2026.5.0 contain a critical authentication vulnerability involving the 'User_ReadBySsoUserOrganizationIdExternalId' stored procedure. When deployed on Microsoft SQL Server, the application declares the '@ExternalId' input parameter with a length of NVARCHAR(50), while the underlying database column is defined as NVARCHAR(300). This discrepancy results in silent truncation of SSO login identifiers. An attacker with a malicious SSO identifier that shares the same first 50 characters as a legitimate user's identifier can successfully authenticate as that victim. This allows the attacker to obtain a victim-scoped access token, leading to unauthorized access to the victim's vault and organizational data. This vulnerability poses a significant risk to organizations relying on SSO for centralized identity management.

## Impact

Successful exploitation results in unauthorized account takeover within a Bitwarden organization. Attackers can gain access to sensitive credentials, secure notes, and other vault items associated with the victim's account. This impacts the confidentiality and integrity of all organizations using the affected Bitwarden Server versions on SQL Server backends, potentially leading to widespread data breaches or administrative account compromise.

## Recommendation

Prioritize patching all internet-facing or organization-critical Bitwarden Server instances to version 2026.5.0 or later. Monitor SQL Server logs for unexpected authentication events or high volumes of SSO login attempts associated with unusually long or truncated external identifiers.
