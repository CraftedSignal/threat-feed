---
title: Unauthenticated Information Disclosure in lamp-cloud via CVE-2026-91996
slug: 2026-09-lamp-cloud-auth-bypass
description: An authentication bypass vulnerability in lamp-cloud versions 5.10.0 and earlier allows unauthenticated attackers to exfiltrate sensitive JVM system properties via insecurely whitelisted API endpoints.
date: "2026-09-15T13:40:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lamp_cloud:lamp_cloud:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - information-disclosure
vendors:
  - lamp-cloud
products:
  - lamp-cloud (<= 5.10.0)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: Attackers can send POST requests to /defGenProject/anno/getProperties to retrieve sensitive information including JVM classpath, filesystem paths, operating system details, and startup secrets.
    confidence_band: high
cves:
  - id: CVE-2026-91996
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91996
rules:
  - title: Detect CVE-2026-91996 Exploitation Attempt
    description: Detects unauthenticated access attempts to the sensitive /anno/getProperties endpoint which discloses JVM system properties.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch lamp-cloud to a version beyond 5.10.0
      owner: IT Operations
      due: 24h
      evidence: Source states lamp-cloud through 5.10.0 is affected.
  hunt_leads:
    - lead: Identify POST requests to /anno/getProperties endpoints in historical web logs
      technique_id: T1082
      data_needed:
        - webserver_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-91996 allows unauthenticated retrieval of JVM system properties via POST requests.
  mitigation_plan:
    - priority: immediate
      action: Remove /*/anno/** whitelist configuration
      owner: IT Operations
      addresses: CVE-2026-91996
      evidence: Vulnerability caused by insecure path pattern whitelisting.
---

CVE-2026-91996 is an authentication bypass vulnerability affecting lamp-cloud versions up to and including 5.10.0. The vulnerability originates from an overly permissive whitelist configuration that allows unauthenticated access to the path pattern /*/anno/**. Defenders should be aware that this configuration enables remote, unauthenticated actors to access sensitive internal endpoints without valid session credentials.

The most critical impact of this vulnerability is the potential for information disclosure via the /defGenProject/anno/getProperties endpoint. By sending a crafted POST request to this endpoint, an attacker can extract the server's full JVM system property map. This data contains sensitive environment information including the full JVM classpath, absolute filesystem paths, operating system metadata, and internal startup configuration secrets. This exposure provides significant reconnaissance value to an attacker, potentially facilitating further exploitation of the underlying host or the application infrastructure.

## Impact

Successful exploitation allows remote, unauthenticated attackers to conduct reconnaissance and gain access to sensitive server-side configuration secrets. The disclosed JVM properties often include internal paths, service secrets, and deployment details that assist in lateral movement or subsequent privilege escalation attempts against the host environment.

## Recommendation

- Upgrade lamp-cloud to a patched version beyond 5.10.0 immediately to remove the insecure authentication bypass.
- Monitor web server access logs for anomalous POST requests targeting the /anno/ URI pattern, specifically the /defGenProject/anno/getProperties endpoint.
- Audit custom authentication filters and path whitelists to ensure no sensitive internal management endpoints are reachable without authorization.
