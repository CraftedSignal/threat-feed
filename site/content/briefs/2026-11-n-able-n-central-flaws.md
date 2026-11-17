---
brief_id: brief-2026-11-17-n-able-n-central-flaws
event_id: brief-2026-11-17-n-able-n-central-flaws
revision: 1
activity_at: "2026-11-17T06:12:51Z"
title: N-able Patches 17 N-central Vulnerabilities
slug: 2026-11-n-able-n-central-flaws
description: N-able has released N-central 2026.4 Hotfix 3 to address 17 security vulnerabilities, while previously disclosed flaws known as 4EverAble2Shell and Agent2Shell are being actively exploited to deploy cryptocurrency miners.
date: "2026-11-17T06:12:51Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://thehackernews.com/2026/11/n-able-patches-17-n-central-flaws-as.html
  observed_at: "2026-11-17T06:12:51Z"
  confidence: high
source_assessment:
  reliability: D
  credibility: "2"
  rating: D2
  likelihood: likely
tags:
  - vulnerability
  - rmm
  - cryptomining
  - remote-code-execution
vendors:
  - N-able
products:
  - N-central
affected_os:
  - Windows
cves:
  - id: CVE-2026-129271
    kev_status: "false"
  - id: CVE-2026-129287
    kev_status: "false"
references:
  - https://thehackernews.com/2026/11/n-able-patches-17-n-central-flaws-as.html
---

## Overview
N-able has released N-central 2026.4 Hotfix 3 to address 17 critical security vulnerabilities. The update includes improvements to authentication, access controls, Agent and Probe security, file and import handling, server hardening, and user management. As part of this update, the configuration option for legacy APIs has been permanently removed.

## Attack Chain
Attackers have been actively exploiting earlier vulnerabilities, collectively tracked as 4EverAble2Shell and Agent2Shell, to deploy cryptocurrency miners. Successful exploitation of the 4EverAble2Shell vulnerabilities previously relied on the legacy API mode, which is now blocked. Unupgraded Agents and Probes remain susceptible to impersonation.

## Impact
Exploitation can allow attackers to gain SYSTEM-level access to Windows systems or run arbitrary code as root. Specific impacts depend on the vulnerability and include authentication bypass, unauthorized command execution, information disclosure, and server-side request forgery (SSRF).

## Recommendation
On-premise customers are advised to upgrade servers immediately. Hosted N-central servers are updated automatically by N-able. All customers must upgrade all Agents and Probes to the latest version to prevent impersonation.
