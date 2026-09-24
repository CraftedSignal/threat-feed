---
title: Authorization Bypass in SigNoz Trace-Funnel Analytics
slug: 2026-09-signoz-auth-bypass
description: SigNoz versions 0.88.0 through 0.141.0 contain an authorization bypass vulnerability allowing unauthenticated remote attackers to query sensitive trace analytics via the trace-funnel endpoint.
date: "2026-09-16T19:52:24Z"
lastmod: "2026-09-24T02:46:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:signoz:signoz:*:*:*:*:*:*:*:*
tags:
  - authorization-bypass
  - api-security
  - observability
  - sql-injection
  - vulnerability
  - web-application
  - webserver
  - injection
  - authentication-bypass
  - jwt
vendors:
  - SigNoz
products:
  - SigNoz (0.88.0 - 0.141.0)
  - SigNoz (0.88.0 <= v < 0.142.1)
  - SigNoz (0.87.0 <= v < 0.142.0)
  - SigNoz (0.8.0 - < 0.143.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The failure to apply authorization wrappers allows unauthenticated remote attackers to query sensitive trace analytics data.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: SigNoz from v0.8.0 before v0.143.0 defaults the JWT tokenizer signing secret to an empty string.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Browser Session Hijacking
    evidence: An unauthenticated attacker who knows the ID of an existing user can forge a valid session token for that user.
    confidence_band: high
cves:
  - id: CVE-2026-92729
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92729
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93292
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93426
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97055
rules:
  - title: Detect Unauthenticated Access to SigNoz Trace-Funnel Endpoint
    description: Detects potential exploitation of CVE-2026-92729 by identifying unauthorized access to the trace-funnel analytics endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-93292 Exploitation - SQL Injection in SigNoz Analytics
    description: Detects potential SQL injection attempts via POST requests to SigNoz analytics endpoints involving service_name or span_name fields.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Exploitation Attempt of CVE-2026-97055 via /api/v2/sessions/context
    description: Detects unauthenticated access or repetitive enumeration attempts against the session context endpoint used to gather information for JWT forging.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 3
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF rule to monitor and block unauthenticated traffic to SigNoz API funnel endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-92729 impact
  hunt_leads:
    - lead: Search logs for unauthenticated POST /api/v1/funnel/ activity
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-92729 allows unauthorized query of analytics
  mitigation_plan:
    - priority: immediate
      action: Upgrade SigNoz to a version post-0.141.0
      owner: IT Operations
      addresses: CVE-2026-92729
      evidence: Vulnerability fixed in newer versions
updates:
  - at: "2026-09-17T17:59:30Z"
    level: L2
    summary: 'added detection rule: Detects CVE-2026-93292 Exploitation - SQL Injection in SigNoz Analytics'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93292
  - at: "2026-09-18T00:03:44Z"
    level: L2
    summary: added coverage for SigNoz (0.87.0 <= v < 0.142.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-93426
  - at: "2026-09-24T02:46:07Z"
    level: L2
    summary: 'added detection rule: Detect Exploitation Attempt of CVE-2026-97055 via /api/v2/sessions/context'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-97055
---

SigNoz versions 0.88.0 through 0.141.0 contain a critical authorization bypass vulnerability within the application's trace-funnel analytics endpoints. The vulnerability stems from a failure to implement necessary authorization wrappers on specific HTTP handlers responsible for processing trace-funnel requests. This oversight allows unauthenticated remote attackers to submit arbitrary funnel definitions to the API. By interacting with these unprotected endpoints, attackers can exfiltrate sensitive observability data, including trace identifiers, request durations, span counts, internal service topology, and error activity metrics. Because these endpoints do not validate user credentials, this vulnerability poses a significant risk for unauthorized information disclosure of internal system architecture and operational telemetry. Defending against this threat requires identifying and restricting access to the affected funnel analytics endpoints or upgrading to a patched version once available.

## Impact

The vulnerability results in unauthorized exposure of sensitive operational data. Successful exploitation allows an attacker to map service dependencies, identify high-frequency error patterns, and monitor traffic volumes, which can be used to inform further reconnaissance against the internal network. No specific victim counts are currently available, but any organization running versions 0.88.0 through 0.141.0 is at risk of remote telemetry exfiltration.

## Recommendation

* Monitor webserver access logs for anomalous POST requests directed at trace-funnel analytic endpoints originating from unauthorized IP ranges.
* Audit ingress traffic to identify unauthenticated requests to SigNoz API paths associated with trace analytics.
* Implement strict network-level access control (e.g., WAF rules or VPN-only access) for the SigNoz API until an upgrade to a patched version is completed.
