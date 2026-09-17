---
title: Unauthenticated SSRF in Kestra OSS via Pebble http() Function
slug: 2026-09-kestra-ssrf
description: An unauthenticated SSRF vulnerability in the Kestra OSS Pebble template engine allows remote attackers to perform arbitrary requests to internal network services and cloud metadata endpoints.
date: "2026-09-17T19:11:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kestra:kestra:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - vulnerability
  - kestra
vendors:
  - Kestra
products:
  - Kestra OSS (<= 1.3.31, < 2.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated attacker can import a malicious Flow YAML and execute it to access internal services.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An unauthenticated attacker can import a malicious Flow YAML and execute it to access internal services.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1566
    technique_name: Phishing
    evidence: Attackers can reach internal services, query cloud provider metadata endpoints to exfiltrate sensitive information.
    confidence_band: med
cves:
  - id: CVE-2026-73247
    cvss: 8.6
    epss: 0.00368
references:
  - https://github.com/advisories/GHSA-r56g-q4p6-m3p6
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73247
iocs:
  - type: ip
    value: 169.254.169.254
ioc_counts:
  ip: 1
rules:
  - title: Detect CVE-2026-73247 Exploitation - Kestra Flow Import Attempt
    description: Detects unauthenticated flow imports to Kestra which may indicate exploitation of the SSRF vulnerability
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
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Kestra OSS to version 1.3.32 or 2.0.0
      owner: IT Operations
      due: 24h
      evidence: Source provided vulnerable version ranges
  mitigation_plan:
    - priority: immediate
      action: Implement egress filtering on Kestra host to block 169.254.169.254 and private subnets
      owner: IT Operations
      addresses: CVE-2026-73247
      evidence: Vulnerability allows SSRF to internal/metadata endpoints
---

Kestra OSS versions up to 1.3.31 and versions prior to 2.0.0 contain a critical Server-Side Request Forgery (SSRF) vulnerability due to insufficient validation in the Pebble template engine's `http()` function. The vulnerability resides in `core/src/main/java/io/kestra/core/runners/pebble/functions/HttpFunction.java`, where user-supplied URLs are processed by `URI.create()` without any sanitization or restriction on target destinations. An unauthenticated attacker can exploit this by uploading a malicious Flow YAML via the Kestra API. The lack of tenant authentication, combined with the ability to define arbitrary target schemes (including `file://` or `gopher://`) and target ranges (including localhost or cloud metadata services like `169.254.169.254`), allows the attacker to exfiltrate cloud credentials, query internal infrastructure, or interact with restricted localhost services. This represents a significant risk for deployments running in cloud environments.

## Attack Chain

1. Attacker identifies a Kestra OSS instance reachable via the network.
2. Attacker crafts a malicious YAML flow configuration containing the `http()` function targeting an internal or metadata endpoint.
3. Attacker uses a `POST` request to `/api/v1/main/flows/import` to upload the malicious flow definition without requiring authentication.
4. Attacker uses a `POST` request to the `/api/v1/main/executions/` endpoint to trigger the flow execution.
5. The Kestra runner evaluates the Pebble template, invoking the `HttpFunction.java` logic with the attacker-controlled URI.
6. The backend performs an outbound HTTP request from the server to the target internal/metadata service.
7. Attacker retrieves the response data through the flow execution output or logs to exfiltrate sensitive metadata or service responses.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass network boundaries. Attackers can exfiltrate sensitive information from cloud provider metadata endpoints (e.g., AWS/GCP/Azure instance metadata service), interact with internal services that are otherwise protected by firewalls, and potentially escalate privileges by harvesting cloud-assigned IAM roles or service credentials.

## Recommendation

Prioritize the immediate mitigation of CVE-2026-73247. Update Kestra OSS to a patched version (>= 1.3.32 or >= 2.0.0). Until updates are deployed, implement strictly scoped network egress controls for the Kestra server to prevent connections to internal RFC1918 subnets and the cloud provider metadata service (`169.254.169.254`). Monitor web server access logs for `POST` requests to `/api/v1/main/flows/import` from untrusted or unexpected source IPs.
