---
title: CVE-2026-88864 - Authorization Bypass in Capgo SSO Provisioning
slug: 2026-09-capgo-sso-bypass
description: An authorization vulnerability in the public.sso_providers table of Capgo allows attackers with an ordinary API key to bypass domain verification and enforce arbitrary SSO settings, leading to authentication disruption.
date: "2026-09-10T15:07:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:capgo:capgo:*:*:*:*:*:*:*:*
tags:
  - sso-bypass
  - cloud-security
  - api-security
vendors:
  - Capgo
products:
  - capgo.app (all versions)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An attacker with a standard Capgo API key can insert a row with status='active' and enforce_sso=true, bypassing the intended backend SSO provisioning route.
    confidence_band: high
cves:
  - id: CVE-2026-88864
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-88864
action_plan:
  priority: elevated
  owners:
    - SOC
    - DevOps
  immediate_actions:
    - action: Audit public.sso_providers for unauthorized rows
      owner: SOC
      due: 24h
      evidence: CVE-2026-88864 exposure of sso_providers table
  mitigation_plan:
    - priority: immediate
      action: Apply row-level security (RLS) on public.sso_providers
      owner: DevOps
      addresses: CVE-2026-88864
      evidence: Source reporting of insufficient write restrictions
---

Capgo (capgo.app) contains a critical authorization flaw (CVE-2026-88864) stemming from improperly restricted access to the public.sso_providers table exposed via Supabase PostgREST. The vulnerability enables any user with a standard Capgo API key to perform direct write operations to this database table. By inserting a row with status set to 'active' and enforce_sso set to 'true', an attacker effectively bypasses the backend provisioning route defined in supabase/functions/_backend/private/sso/providers.ts. 

This bypass invalidates critical security controls, including the Enterprise plan entitlement checks, domain-ownership verification through DNS TXT records, and the mandatory transition from pending_verification to verified status. Consequently, the application trusts these forged entries during SSO discovery and enforcement logic, including the unauthenticated /private/sso/check-domain preflight endpoint. This allows an attacker to assert SSO enforcement for arbitrary domains, effectively hijacking the login flow for legitimate users. As of the advisory date, no patch is available for this vulnerability.

## Impact

Successful exploitation results in the unauthorized assertion of SSO enforcement for arbitrary domains. This disrupts authentication services, potentially leading to denial-of-service for legitimate users who are forced into invalid SSO workflows. The vulnerability bypasses the Enterprise plan tiering, allowing unauthorized access to enterprise-grade features. No specific victim counts were reported, but the flaw affects all deployments of the capgo.app platform.

## Recommendation

Prioritize monitoring for anomalous database write activity or API key usage until a vendor patch is issued. 
- Restrict access to the Supabase PostgREST interface to known-good administrative IP ranges.
- Audit logs for unauthorized INSERT or UPDATE operations on the public.sso_providers table.
- Review all existing entries in the public.sso_providers table for unexpected configurations that deviate from legitimate enterprise tenant provisioning.
- Implement strict row-level security (RLS) policies within Supabase to prevent API-key-based writes to the sso_providers table.
