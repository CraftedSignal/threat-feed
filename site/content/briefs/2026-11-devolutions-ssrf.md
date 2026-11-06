---
brief_id: brief-2026-11-06-devolutions-ssrf
event_id: brief-2026-11-06-devolutions-ssrf
revision: 1
activity_at: "2026-11-06T21:29:42Z"
title: 'Devolutions Server: Active Directory credential validation SSRF (CVE-2026-120715)'
slug: 2026-11-devolutions-ssrf
description: An authenticated low-privileged user can exploit a server-side request forgery (SSRF) vulnerability in Devolutions Server 2026.3.12.0 and earlier to capture the NetNTLMv2 hash of the service account.
date: "2026-11-06T21:29:42Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:devolutions:devolutions_server:*:*:*:*:*:*:*:*
vendors:
  - Devolutions
products:
  - Devolutions Server (<= 2026.3.12.0)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: This vulnerability allows an authenticated user with low privileges to force the application to make network requests to an attacker-controlled domain, enabling the capture of the NetNTLMv2 hash associated with the DVLS service account.
    confidence_band: high
cves:
  - id: CVE-2026-120715
    cvss: 8.1
    epss: 0.00142
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120715
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Devolutions Server to the patched version that addresses CVE-2026-120715.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability CVE-2026-120715 impacts Devolutions Server versions 2026.3.12.0 and earlier.
  hunt_leads:
    - lead: Identify authenticated users submitting requests to the Active Directory validation endpoint that include external, non-corporate domain names.
      technique_id: T1555
      data_needed:
        - Application request logs
        - Web server logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability involves an attacker-controlled domain name in the request provided to the AD credential validation functionality.
  mitigation_plan:
    - priority: immediate
      action: Apply security updates for Devolutions Server to remediate CVE-2026-120715.
      owner: IT Operations
      addresses: CVE-2026-120715
      evidence: Remediation of the SSRF vulnerability requires updating the affected product.
---

Devolutions Server versions 2026.3.12.0 and earlier are affected by a server-side request forgery (SSRF) vulnerability in the Active Directory credential validation functionality. An authenticated low-privileged user can supply an attacker-controlled domain name to the validation endpoint, forcing the server to authenticate against the external host. This results in the leakage of the DVLS service account's NetNTLMv2 hash to the attacker.

## Impact

Successful exploitation allows a low-privileged user to obtain the NetNTLMv2 hash of the service account, which can be subsequently cracked offline or used for NTLM relay attacks to gain further access within the Active Directory environment.

## Recommendation

- Upgrade Devolutions Server to the version containing the fix for CVE-2026-120715.
- Audit logs for the Active Directory credential validation endpoint to identify unusual or external domain requests.
- Monitor service account activity for signs of unauthorized NTLM authentication or relay attempts.
