---
brief_id: brief-2026-10-28-juniper-ssr-auth-bypass
event_id: brief-2026-10-28-juniper-ssr-auth-bypass
revision: 4
activity_at: "2026-10-29T20:15:56Z"
revision_history:
  - revision: 2
    at: "2026-10-28T19:24:42Z"
    checksum: sha256:5bd2c54b8d61ec37d4ac5e33247351f4d79c110405415e3a447e53db0a3327ad
    summary: poc_available
    changed_fields:
      - claim_state
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-103409&utm_source=rss&utm_medium=rss
  - revision: 3
    at: "2026-10-28T22:49:50Z"
    checksum: sha256:24858ddf3225de5fde94dcd88907674cc17d5bb7f2f8cf5481450d8077ab5a52
    summary: added CVE-2026-103407
    changed_fields:
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103407
  - revision: 4
    at: "2026-10-29T20:15:56Z"
    checksum: sha256:3133fc2fc8d86f559235f4ab196b0c87fb45624ed532cd9cec31f0b4fabbc297
    summary: added coverage for Session Smart Router +1 products
    changed_fields:
      - action_plan
      - cves
      - lastmod
      - priority_score
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-106079
title: 'Juniper Networks Session Smart Router: Missing authentication for critical function (CVE-2026-103409)'
slug: 2026-10-juniper-ssr-auth-bypass
description: A missing authentication vulnerability in Juniper Networks Session Smart Router allows unauthenticated network-based attackers to escalate privileges via crafted URL parameters on non-onboarded devices.
date: "2026-10-28T18:36:56Z"
lastmod: "2026-10-29T20:14:55Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE-2026-103409 details
cpes:
  - cpe:2.3:a:juniper:session_smart_router:*:*:*:*:*:*:*:*
  - cpe:2.3:a:juniper:session_smart_conductor:*:*:*:*:*:*:*:*
  - cpe:2.3:a:juniper_networks:session_smart_router:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=CVE-2026-103409&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - network-security
  - authentication-bypass
  - privilege-escalation
  - remote-code-execution
vendors:
  - Juniper Networks
products:
  - Session Smart Router
  - Session Smart Conductor
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A Missing authentication for critical function vulnerability in Juniper Networks Session Smart Router allows an unauthenticated network-based attacker to obtain administrative privileges.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated network-based attacker to obtain administrative privileges by passing crafted URL parameters to an insecure endpoint running as root.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in AccessManager... allows an attacker... to achieve arbitrary command execution as root in the YANG configuration.
    confidence_band: high
cves:
  - id: CVE-2026-103409
    cvss: 9.8
    epss: 0.00347
    kev_status: "false"
  - id: CVE-2026-103401
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-103402
    cvss: 8.8
    kev_status: "false"
  - id: CVE-2026-103403
    cvss: 8.8
    epss: 0.01182
    kev_status: "false"
  - id: CVE-2026-103408
    cvss: 8.8
    epss: 0.00309
    kev_status: "false"
  - id: CVE-2026-103411
    cvss: 7.1
    epss: 0.00174
    kev_status: "false"
  - id: CVE-2026-103407
    cvss: 8.8
    epss: 0.00229
    kev_status: "false"
  - id: CVE-2026-106079
    cvss: 8.8
    epss: 0.01182
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103409
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103401
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103402
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103403
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103408
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103411
  - https://sploitus.com/exploit?id=CVE-2026-103409&utm_source=rss&utm_medium=rss
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103407
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4234
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106079
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Onboard all active Session Smart Router appliances to Mist or Conductor to neutralize CVE-2026-103409.
      owner: IT Operations
      due: 24h
      evidence: The issue can no longer be exploited once a device is onboarded to Mist/Conductor.
    - action: Identify all deployed Juniper Session Smart Router and Conductor instances and confirm patch status.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects Session Smart Router and Session Smart Conductor
    - action: Audit accounts with config-write privileges on Session Smart Router and Conductor interfaces.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability requires config-write privileges to exploit.
  hunt_leads:
    - lead: Identify unauthorized access attempts to administrative web endpoints on newly deployed, non-onboarded Session Smart Routers.
      technique_id: T1190
      data_needed:
        - Web server access logs from SSR devices
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attacker exploits by passing crafted URL parameters to an insecure endpoint.
    - lead: Monitor for unauthorized file modifications or write operations within the model cache directory.
      technique_id: T1068
      data_needed:
        - System file integrity audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An attacker with write access to the model cache directory can execute arbitrary code
    - lead: Identify suspicious or anomalous YANG configuration changes that include shell metacharacters or unexpected command invocations.
      technique_id: T1059
      data_needed:
        - Session Smart Router/Conductor administrative audit logs
        - YANG configuration audit trails
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation occurs via the YANG configuration interface.
  mitigation_plan:
    - priority: immediate
      action: Restrict write permissions for the model cache directory to the minimum required service accounts.
      owner: IT Operations
      addresses: CVE-2026-103402
      evidence: Vulnerability depends on attacker having write access to the model cache directory
    - priority: immediate
      action: Patch Session Smart Router and Session Smart Conductor systems as soon as the vendor fix is released.
      owner: IT Operations
      addresses: CVE-2026-106079
      evidence: NVD advisory for CVE-2026-106079.
updates:
  - at: "2026-10-28T18:37:28Z"
    level: L2
    summary: added CVE-2026-103408, CVE-2026-103411
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103408
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103411
  - at: "2026-10-28T19:23:52Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CVE-2026-103409&utm_source=rss&utm_medium=rss
  - at: "2026-10-28T22:47:54Z"
    level: L2
    summary: added CVE-2026-103407
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-103407
  - at: "2026-10-29T20:14:55Z"
    level: L2
    summary: added coverage for Session Smart Router +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-106079
---

CVE-2026-103409 is a missing authentication for critical function vulnerability affecting Juniper Networks Session Smart Router. An unauthenticated attacker can exploit this via crafted URL parameters sent to a root-level endpoint. This flaw is only exploitable on devices that have not yet been onboarded to Mist or Conductor management systems. Once a device is successfully onboarded, the vulnerability is no longer exploitable.

## Impact

An unauthenticated network-based attacker can achieve administrative privileges on affected appliances, potentially leading to full device compromise.

## Recommendation

Prioritize the onboarding of all new Session Smart Router appliances to Mist or Conductor immediately upon deployment. This action renders the vulnerability non-exploitable. Monitor network traffic directed at unmanaged or staging routers for unauthorized access attempts to administrative endpoints.
