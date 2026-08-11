---
title: Undertow AJP Authentication Bypass via CVE-2026-15554
slug: 2026-08-undertow-ajp-auth-bypass
description: The Undertow AJP listener incorrectly trusts ssl_cert and is_ssl attributes within the AJP protocol without validating a shared secret, allowing unauthenticated attackers to bypass CLIENT-CERT authentication.
date: "2026-08-11T09:39:50Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authentication-bypass
  - network-security
vendors:
  - Red Hat
products:
  - Undertow
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This enables an unauthenticated attacker with direct TCP access to port 8009 to bypass CLIENT-CERT authentication by injecting a forged X.509 certificate via the AJP protocol.
    confidence_band: high
cves:
  - id: CVE-2026-15554
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15554
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Restrict network access to AJP port 8009 to trusted proxies only
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthenticated access via direct TCP connection to port 8009.
  mitigation_plan:
    - priority: immediate
      action: Patch Undertow to version containing CVE-2026-15554 fix
      owner: IT Operations
      addresses: CVE-2026-15554
      evidence: NVD vulnerability record
---

CVE-2026-15554 is a critical authentication bypass vulnerability affecting the AJP (Apache Jserv Protocol) listener within Red Hat's Undertow web server. The flaw arises because the listener honors the 'ssl_cert' and 'is_ssl' attributes provided within an incoming AJP request packet without requiring a pre-shared secret or cryptographic validation. 

An unauthenticated attacker who can establish a direct TCP connection to the AJP port (default 8009) can inject a forged X.509 certificate into these headers. Because the server trusts these forged attributes, it incorrectly assumes the connection is secured via a valid client certificate, allowing the attacker to bypass CLIENT-CERT authentication requirements. This is particularly dangerous in environments where internal or management interfaces rely on AJP-based mutual TLS for access control. Defenders should prioritize limiting access to port 8009 to trusted, internal-only infrastructure components such as reverse proxies.

## Impact

Successful exploitation allows unauthenticated attackers to bypass CLIENT-CERT authentication, potentially granting unauthorized access to administrative or restricted application endpoints. This vulnerability exposes services relying on certificate-based identity verification, which could lead to unauthorized data access or service manipulation within affected Red Hat Undertow deployments. The CVSS base score of 7.4 reflects the high impact on confidentiality and integrity for exposed application components.

## Recommendation

- Restrict network access to the AJP listener (default port 8009) to only authorized, trusted reverse proxy IP addresses.
- Patch affected Undertow versions immediately upon vendor release.
- Audit network egress and ingress for traffic targeting TCP port 8009 to identify unauthorized sources or unexpected AJP request patterns.
