---
brief_id: brief-2026-04-21-openclaw-auth-bypass
event_id: brief-2026-04-21-openclaw-auth-bypass
revision: 3
activity_at: "2026-10-29T18:04:56Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:52af697b3638c2ef52f946c54390680709b7ccdb905ca6279baef63e06460154
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
  - revision: 3
    at: "2026-10-29T18:04:56Z"
    checksum: sha256:af1a5ed46d310b1361e2f211446c58b3651d369ba1d0136c42a321d0854c2d9f
    summary: OS linux
    changed_fields:
      - affected_os
      - affected_vendors
      - claim_state
      - cpes
      - cves
      - iocs
      - lastmod
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KALETH4-CVE-2026-41303&utm_source=rss&utm_medium=rss
title: OpenClaw Authorization Bypass Vulnerability (CVE-2026-41303)
slug: 2026-04-21-openclaw-auth-bypass
description: OpenClaw before 2026.3.28 contains an authorization bypass vulnerability allowing non-approvers to resolve pending exec approvals via Discord text commands.
date: "2026-04-21T00:16:31Z"
lastmod: "2026-10-29T18:04:00Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:openclaw:openclaw:*:*:*:*:*:node.js:*:*
tags:
  - authorization bypass
  - discord
  - privilege escalation
vendors:
  - OpenClaw
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41303
    cvss: 8.8
    epss: 0.00408
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41303
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-98hh-7ghg-x6rq
  - https://www.vulncheck.com/advisories/openclaw-authorization-bypass-in-discord-text-approval-commands
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KALETH4-CVE-2026-41303&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Discord Command Abuse for OpenClaw Approval Bypass
    description: Detects suspicious Discord commands potentially used to bypass OpenClaw approval processes based on command keywords associated with approval workflows
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: OpenClaw Unauthorized Approval Activity
    description: Detects unusual approval activity originating from IP addresses or user accounts not in the authorized approvers list based on observed access patterns.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-10-29T18:04:00Z"
    level: L1
    summary: OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-KALETH4-CVE-2026-41303&utm_source=rss&utm_medium=rss
---

OpenClaw, a yet-to-be-defined application, is vulnerable to an authorization bypass (CVE-2026-41303) affecting versions prior to 2026.3.28. This vulnerability enables unauthorized users to approve pending execution requests by exploiting Discord text commands. Attackers can bypass the `channels.discord.execApprovals.approvers` allowlist, designed to restrict approval capabilities to authorized personnel. The vulnerability was reported on April 20, 2026. Successful exploitation grants attackers elevated privileges, potentially leading to unauthorized code execution and system compromise. This is critical for defenders to address if OpenClaw is used in their environments, as the bypass can subvert intended access controls.

## Attack Chain

1.  Attacker identifies a pending execution request within the OpenClaw system.
2.  Attacker crafts a malicious Discord text command designed to approve the request.
3.  Attacker sends the crafted command to the Discord channel monitored by OpenClaw.
4.  OpenClaw processes the command without properly validating the sender's authorization.
5.  The system bypasses the `channels.discord.execApprovals.approvers` allowlist.
6.  The pending execution request is approved, despite the attacker lacking the necessary permissions.
7.  The approved execution request is initiated on the host system.
8.  The attacker achieves arbitrary code execution on the host system.

## Impact

Successful exploitation of this vulnerability allows unauthorized users to approve and execute arbitrary commands on the target system. Given that OpenClaw manages execution requests, this could lead to significant compromise, including data breaches, system takeover, or denial of service. The vulnerability poses a significant risk to organizations relying on OpenClaw for managing execution approvals, as it undermines the intended security controls and could enable malicious actors to perform privileged actions without proper authorization.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to remediate the vulnerability (CVE-2026-41303).
*   Monitor Discord channels used by OpenClaw for suspicious commands that attempt to approve execution requests, and create rules to detect anomalies related to command usage and origins.
*   Implement stricter input validation and authorization checks within OpenClaw to prevent command spoofing and unauthorized access.
