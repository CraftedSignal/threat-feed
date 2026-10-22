---
brief_id: brief-2026-10-22-netmaker-auth-bypass
event_id: brief-2026-10-22-netmaker-auth-bypass
revision: 1
activity_at: "2026-10-22T14:16:59Z"
title: 'Netmaker: Authorization bypass in updateExtClient handler (CVE-2026-115325)'
slug: 2026-10-netmaker-auth-bypass
description: Netmaker versions up to 1.7.0 contain an authorization bypass vulnerability allowing authenticated external clients to modify or exfiltrate configuration data from arbitrary networks via the updateExtClient handler.
date: "2026-10-22T14:16:59Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Checked against NVD advisory
cpes:
  - cpe:2.3:a:netmaker:netmaker:*:*:*:*:*:*:*:*
vendors:
  - Netmaker
products:
  - Netmaker (<= 1.7.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers with external client permissions on one network can send PUT requests to /api/extclients/{network}/{clientid} to replace public keys.
    confidence_band: high
cves:
  - id: CVE-2026-115325
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115325
rules:
  - title: Detect CVE-2026-115325 Exploitation - Unauthorized API Request to updateExtClient
    description: Detects potentially unauthorized PUT requests to the updateExtClient handler. This rule identifies API calls that might indicate an attempt to bypass authorization for external client management.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch Netmaker instances
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects Netmaker through 1.7.0
  hunt_leads:
    - lead: Identify PUT requests to /api/extclients/ in web access logs
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit uses PUT requests to specific endpoint
  mitigation_plan:
    - priority: immediate
      action: Upgrade Netmaker beyond 1.7.0
      owner: IT Operations
      addresses: CVE-2026-115325
      evidence: NVD source states version 1.7.0 is vulnerable
---

Netmaker versions through 1.7.0 are vulnerable to an authorization bypass in the updateExtClient handler. This vulnerability enables a user who already possesses external client permissions on a single network to perform unauthorized operations on other networks managed by the same Netmaker instance. 

## Impact

Successful exploitation allows an attacker to send crafted PUT requests to the /api/extclients/{network}/{clientid} endpoint. This permits the attacker to replace public keys, disable external clients, or exfiltrate sensitive WireGuard private keys from networks they should not have access to.

## Recommendation

- Upgrade Netmaker to a version beyond 1.7.0 immediately.
- Audit logs for PUT requests to /api/extclients/ where the {network} identifier in the URI does not align with the authorized scope of the requesting user.
- Review all external client configurations for unexpected public key changes or unauthorized state modifications.
