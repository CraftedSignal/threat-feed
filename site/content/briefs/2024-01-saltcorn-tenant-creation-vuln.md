---
title: Saltcorn Data Tenant Admin Privilege Escalation via Tenant Creation
slug: 2024-01-saltcorn-tenant-creation-vuln
description: A vulnerability in Saltcorn Data allows tenant admins to gain unauthorized admin-level access to the root domain by creating tenants in the root domain's schema instead of their own.
date: "2024-01-30T12:00:00Z"
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - cloud
vendors:
  - Saltcorn
products:
  - Saltcorn Data
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-9237-rg5p-rhfw
rules:
  - title: Detect Saltcorn Unauthorized Tenant Creation
    description: Detects attempts to create tenants via the /tenant/create endpoint, potentially indicating unauthorized tenant creation in the root domain.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Saltcorn Tenant Creation with Non-Admin Role
    description: Detects attempts to create tenants via the /tenant/create endpoint by users without admin role. This assumes additional logging context provides role details.
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
---

A privilege escalation vulnerability exists in Saltcorn Data, affecting versions prior to 1.4.4, versions between 1.5.0-beta.0 and 1.5.2, and versions between 1.6.0-alpha.0 and 1.6.0-beta.2. The vulnerability allows tenant administrators, who are logged out of the root domain but authenticated within their own tenant space, to create new tenants within the root domain's database schema. This occurs because the system incorrectly evaluates the tenant's role within the context of the root domain…
