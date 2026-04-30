---
title: Saltcorn Data Tenant Admin Privilege Escalation via Tenant Creation
slug: 2024-01-saltcorn-tenant-creation-vuln
description: A vulnerability in Saltcorn Data allows tenant admins to gain unauthorized admin-level access to the root domain by creating tenants in the root domain's schema instead of their own.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
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

A privilege escalation vulnerability exists in Saltcorn Data, affecting versions prior to 1.4.4, versions between 1.5.0-beta.0 and 1.5.2, and versions between 1.6.0-alpha.0 and 1.6.0-beta.2. The vulnerability allows tenant administrators, who are logged out of the root domain but authenticated within their own tenant space, to create new tenants within the root domain's database schema. This occurs because the system incorrectly evaluates the tenant's role within the context of the root domain during tenant creation. By appending `/tenant/create` to their tenant URL, a tenant admin with sufficient privileges in their tenant can bypass root domain restrictions and create subtenants in the root domain.

## Attack Chain

1. Attacker authenticates to their assigned tenant with administrator privileges.
2. Attacker logs out of the root domain (e.g., `saltcorn.com`).
3. Attacker navigates to the tenant-specific URL, where they have admin rights.
4. Attacker appends `/tenant/create` to the tenant URL (e.g., `tenant.saltcorn.com/tenant/create`).
5. The application evaluates the user's role in the context of the tenant (admin role).
6. The application then attempts to create a new tenant but incorrectly does so under the root domain's `_sc_tenants` schema instead of the tenant's.
7. The new tenant is created in the root domain (PUBLIC SCHEMA > `_sc_tenants`).
8. The attacker effectively gains the ability to create tenants in the root domain, escalating privileges.

## Impact

Successful exploitation of this vulnerability grants tenant administrators unauthorized admin-level access to the root domain of the Saltcorn Data instance. This could lead to unauthorized modification or deletion of data within the root domain, disruption of service for all tenants hosted on the instance, and potential further escalation of privileges within the system. The advisory does not state specific victim counts or sectors targeted, but the impact is significant due to the potential for widespread disruption and data compromise.

## Recommendation

*   Upgrade Saltcorn Data to a patched version (>= 1.4.4, >= 1.5.2, or >= 1.6.0-beta.2) to remediate the vulnerability (reference: Affected Packages).
*   Monitor web server logs for requests to the `/tenant/create` endpoint originating from tenant administrator sessions to detect potential exploitation attempts (reference: Sigma rule `Detect Saltcorn Unauthorized Tenant Creation`).
*   Implement additional server-side validation to ensure tenant creation requests are properly scoped to the originating tenant's schema (reference: advisory summary).
