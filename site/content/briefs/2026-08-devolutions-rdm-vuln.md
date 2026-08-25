---
title: Data Manipulation Vulnerability in Devolutions Remote Desktop Manager
slug: 2026-08-devolutions-rdm-vuln
description: A vulnerability in Devolutions Remote Desktop Manager allows a remote, unauthenticated attacker to manipulate data, leading to unauthorized modification risks.
date: "2026-08-25T09:59:17Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:hcltech:dryice_myxalytics:6.3:*:*:*:*:*:*:*
  - cpe:2.3:a:hcltech:dryice_myxalytics:6.4:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-access
vendors:
  - Devolutions
products:
  - Remote Desktop Manager
cves:
  - id: CVE-2024-42176
    cvss: 2.6
    epss: 0.00221
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2982
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Vulnerability Management
  immediate_actions:
    - action: Inventory all systems running Devolutions Remote Desktop Manager.
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommends remediation via patch.
  mitigation_plan:
    - priority: immediate
      action: Patch Remote Desktop Manager to the version resolving CVE-2024-42176.
      owner: IT Operations
      addresses: CVE-2024-42176
      evidence: BSI Security Advisory WID-SEC-2026-2982.
---

The German Federal Office for Information Security (BSI) has released an advisory regarding a security vulnerability in Devolutions Remote Desktop Manager. The vulnerability, tracked as CVE-2024-42176, allows a remote and unauthenticated attacker to manipulate data within the application. This issue stems from improper validation of input or integrity checks, enabling the unauthorized modification of data handled by the Remote Desktop Manager software. Organizations utilizing this software are advised to review the vulnerability details and apply the vendor-provided patches to prevent potential data integrity compromises. Given that Remote Desktop Manager is often used for centralized access management, successful exploitation could lead to wider systemic impacts if sensitive connection profiles or credentials stored within the application are altered by unauthorized parties.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to modify data within Devolutions Remote Desktop Manager. This can lead to unauthorized changes to application configuration or session parameters, potentially resulting in security bypasses or the redirection of remote connections to attacker-controlled infrastructure.

## Recommendation

Prioritize the identification of all instances of Devolutions Remote Desktop Manager across the organization to ensure they are tracked for patching. Monitor vendor security advisories for the specific patch version addressing CVE-2024-42176 and apply updates immediately. Given the lack of specific log-based indicators in this advisory, focus on asset management and patch compliance via standard vulnerability management workflows.
