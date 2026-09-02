---
title: EasyAdminBundle Access Control Bypass via Route Name Manipulation
slug: 2026-09-easyadmin-access-bypass
description: EasyAdminBundle fails to re-validate Symfony access control rules when swapping controllers for custom actions, allowing low-privilege users to bypass path-based security and access restricted routes.
date: "2026-09-02T18:04:16Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TungNGo02
cpes:
  - cpe:2.3:a:easycorp:easyadmin-bundle:*:*:*:*:*:*:*:*
tags:
  - web-application
  - security-bypass
  - cve-2026-81892
vendors:
  - EasyCorp
products:
  - EasyAdminBundle (< 4.29.16)
  - EasyAdminBundle (5.0.0 - 5.5.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker who can reach a single EasyAdmin URL and knows a target route's name can execute that route's controller, bypassing the path-based rule.
    confidence_band: high
cves:
  - id: CVE-2026-81892
    cvss: 8.1
    epss: 0.0025
references:
  - https://github.com/advisories/GHSA-g2fm-8hr4-j82h
  - https://nvd.nist.gov/vuln/detail/CVE-2026-81892
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Upgrade EasyAdminBundle to 4.29.16 or 5.5.1
      owner: IT Operations
      due: 48h
      evidence: Fixed in 4.29.16 and 5.5.1
  mitigation_plan:
    - priority: immediate
      action: Enforce controller-level authorization (#[IsGranted]) on all restricted admin routes.
      owner: Application Security
      addresses: CVE-2026-81892
      evidence: Workaround suggests using controller-level authorization
---

EasyAdminBundle (CVE-2026-81892) contains a critical access control bypass vulnerability affecting versions 4.x before 4.29.16 and 5.x before 5.5.1. The issue resides in the custom-action dispatcher, which handles navigation via `Action::linkToRoute()` or `MenuItem::linkToRoute()`. When a user provides a `routeName` query parameter, EasyAdmin performs a controller swap on the `kernel.controller` event.

Crucially, this swap occurs after the Symfony security firewall has already evaluated `access_control` against the primary dashboard URL. Because the provided `routeName` is not re-validated against path-based firewall rules, an attacker can access restricted routes that rely solely on `security.yaml` definitions for protection. This bypass is limited to path-based access controls; routes that utilize controller-level authorization such as `#[IsGranted]` or `denyAccessUnlessGranted()` are not affected, as those checks are re-evaluated against the new controller. The vulnerability allows unauthorized users to interact with sensitive administrative functionality if they can identify the target route name.

## Impact

The vulnerability allows low-privileged users to access sensitive administrative routes protected only by path-based firewall configurations. If an application's security architecture relies on `access_control` rules to segment backend capabilities, an attacker can bypass these restrictions to gain unauthorized access to data or perform administrative functions. Routes that do not explicitly implement controller-level security checks are at high risk of exposure.

## Recommendation

* Upgrade EasyAdminBundle to version 4.29.16 or 5.5.1 immediately to incorporate the required re-evaluation of `access_control` rules during custom-action dispatch.
* Audit all sensitive routes to ensure they implement controller-level security using `#[IsGranted]` or `denyAccessUnlessGranted()` as a secondary defense-in-depth measure.
* Monitor web application logs for unexpected access to admin-related controller paths that are typically hidden from low-privileged users.
