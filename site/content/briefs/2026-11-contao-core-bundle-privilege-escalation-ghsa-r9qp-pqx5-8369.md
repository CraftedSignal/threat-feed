---
brief_id: brief-2026-11-21-contao-core-bundle-privilege-escalation-ghsa-r9qp-pqx5-8369
event_id: brief-2026-11-21-contao-core-bundle-privilege-escalation-ghsa-r9qp-pqx5-8369
revision: 1
activity_at: "2026-11-21T02:05:33Z"
title: Contao core-bundle Privilege Escalation via theme_import
slug: 2026-11-contao-core-bundle-privilege-escalation-ghsa-r9qp-pqx5-8369
description: Non-admin users with delegated user management permissions can grant themselves the 'theme_import' capability, leading to arbitrary PHP execution and bypassing security controls introduced in v5.7.3.
date: "2026-11-21T02:05:33Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - privilege-escalation
  - rce
vendors:
  - Contao
products:
  - composer/contao/core-bundle
cves:
  - id: CVE-2026-104883
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-r9qp-pqx5-8369
---

## Overview
Contao core-bundle contains a privilege escalation vulnerability where non-admin users with delegated user management permissions can grant themselves the 'theme_import' capability. While commit 2b83a60f7763 (introduced in v5.7.3) added `TemplateEditorModuleVoter` to restrict the 'tpl_editor' backend module, the 'theme_import' capability within the 'themes' checkbox field lacks corresponding voter logic. This allows a delegated user manager to grant themselves the 'theme_import' permission, which enables arbitrary PHP execution.

## Attack Chain
1. A non-admin backend user with delegated user management permissions (the 'user' or 'group' module) edits a group or account.
2. The user adds 'themes' to the modules field and 'theme_import' to the themes field.
3. The application accepts these permissions, as they are not restricted by the `TemplateEditorModuleVoter`.
4. Upon re-authentication, the user gains access to 'theme_import', enabling arbitrary PHP execution.

## Impact
A delegated user/group manager can escalate privileges to execute arbitrary PHP code on the server, resulting in full system compromise. This bypasses the protections introduced in v5.7.3.

## Recommendation
Upgrade to the patched versions:
- For branch 5.0.x: Upgrade to 5.3.50 or later.
- For branch 5.4.x: Upgrade to 5.7.12 or later.
