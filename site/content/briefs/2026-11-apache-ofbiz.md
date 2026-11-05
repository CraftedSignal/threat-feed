---
brief_id: brief-2026-11-04-apache-ofbiz
event_id: brief-2026-11-04-apache-ofbiz
revision: 3
activity_at: "2026-11-05T19:22:51Z"
revision_history:
  - revision: 2
    at: "2026-11-05T12:56:03Z"
    checksum: sha256:9040f4005f58856e0ad7c01c2ae79d793552d1e9456c4ecf614040411dcf49fd
    summary: new product
    changed_fields:
      - affected_products
      - claim_state
      - lastmod
      - references
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4357
  - revision: 3
    at: "2026-11-05T19:22:51Z"
    checksum: sha256:55518bb8535cfe26419d916f4b60bbb5967de374d060fa2e5c52734b30ea4bb1
    summary: ofbiz version < 24.09.08
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/apache-ofbiz-24-09-08-unauthenticated-rce-auth-bypass-nov-2026
title: 'Apache OFBiz: Multiple vulnerabilities (CVE-2026-66903, CVE-2026-68524)'
slug: 2026-11-apache-ofbiz
description: Apache OFBiz versions prior to 24.09.08 are vulnerable to critical flaws including authenticated path traversal in Catalog Image Management and pre-authentication remote code execution.
date: "2026-11-04T21:08:40Z"
lastmod: "2026-11-05T19:22:08Z"
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
  validation_status: Needs environment validation of the vulnerability triggers
cpes:
  - cpe:2.3:a:apache:ofbiz:*:*:*:*:*:*:*:*
vendors:
  - Apache
products:
  - OFBiz (< 24.09.08)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Pre-Authentication Remote Code Execution via Attacker-Controlled Screen.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Pre-Authentication Remote Code Execution via Attacker-Controlled Screen.
    confidence_band: high
cves:
  - id: CVE-2026-66903
    kev_status: "false"
  - id: CVE-2026-68524
    kev_status: "false"
  - id: CVE-2026-83542
    kev_status: unknown
  - id: CVE-2026-82907
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/516
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4357
  - https://pwn.watch/i/apache-ofbiz-24-09-08-unauthenticated-rce-auth-bypass-nov-2026
  - https://www.openwall.com/lists/oss-security/2026/11/04/9
  - https://ofbiz.apache.org/security.html
  - https://www.cve.org/CVERecord?id=CVE-2026-83542
  - https://www.cve.org/CVERecord?id=CVE-2026-82907
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Apache OFBiz to 24.09.08
      owner: IT Operations
      due: 24h
      evidence: Users are advised to upgrade to Apache OFBiz 24.09.08, which addresses these vulnerabilities.
  hunt_leads:
    - lead: Identify unauthenticated access to screen-related application endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-uri-stem, cs-method, sc-status)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Pre-Authentication Remote Code Execution via Attacker-Controlled Screen.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 24.09.08
      owner: IT Operations
      addresses: CVE-2026-66903, CVE-2026-68524
      evidence: Users are advised to upgrade to Apache OFBiz 24.09.08, which addresses these vulnerabilities.
updates:
  - at: "2026-11-05T12:53:28Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4357
  - at: "2026-11-05T19:22:08Z"
    level: L2
    summary: ofbiz version < 24.09.08
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/apache-ofbiz-24-09-08-unauthenticated-rce-auth-bypass-nov-2026
---

The Apache Software Foundation has released security updates for Apache OFBiz to address multiple vulnerabilities, including two identified CVEs. The most severe issue allows for pre-authentication remote code execution, while the second vulnerability enables path traversal within the Catalog Image Management component. These vulnerabilities affect all versions prior to 24.09.08.

## Impact
Successful exploitation of CVE-2026-68524 could allow an unauthenticated attacker to execute arbitrary code on the underlying server. CVE-2026-66903 could allow an authenticated user to perform unauthorized file system access.

## Recommendation
- Upgrade all instances of Apache OFBiz to version 24.09.08 or later immediately.
- Audit existing OFBiz installations for suspicious access patterns to the Catalog Image Management component.
- Review web server access logs for anomalous requests to screen-related endpoints that may indicate attempts to trigger the pre-authentication RCE.
