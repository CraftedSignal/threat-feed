---
title: CVE-2026-19000 Server-Side Request Forgery in JeecgBoot
slug: 2026-08-jeecgboot-ssrf
description: An unauthenticated server-side request forgery (SSRF) vulnerability in the JeecgBoot 'Anonymous Chat Attachment Parser' allows remote attackers to perform unauthorized requests via the /airag/chat/send endpoint.
date: "2026-08-06T07:22:09Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - ssrf
  - web-vulnerability
products:
  - JeecgBoot
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation leads to server-side request forgery. The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-19000
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19000
  - https://github.com/jeecgboot/JeecgBoot/issues/9672
rules:
  - title: Detect CVE-2026-19000 Exploitation - SSRF Attempt on JeecgBoot
    description: Detects unauthorized access attempts to the vulnerable /airag/chat/send endpoint associated with CVE-2026-19000.
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
    - action: Deploy WAF rule to block requests to /airag/chat/send
      owner: SOC
      due: 24h
      evidence: NVD vulnerability disclosure
  hunt_leads:
    - lead: Search logs for unusual outbound connections originating from the web server
      technique_id: T1190
      data_needed:
        - Network connection logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: SSRF vulnerability allows external requests from server
---

A server-side request forgery (SSRF) vulnerability, identified as CVE-2026-19000, has been disclosed in JeecgBoot versions up to 3.9.2. The vulnerability resides within the Anonymous Chat Attachment Parser component, specifically in an undocumented function associated with the /airag/chat/send endpoint. Remote, unauthenticated attackers can exploit this flaw to induce the application server to perform unauthorized HTTP requests to internal or external resources. Given the availability of public exploit material, there is a risk of active exploitation for reconnaissance or interaction with internal services that are not directly exposed to the internet. Defenders should prioritize patching or restricting access to the affected endpoint until a vendor-supplied update is available.

## Impact

Successful exploitation of this SSRF vulnerability may allow attackers to bypass network perimeter controls to scan internal networks, retrieve sensitive metadata from cloud environments (e.g., IMDS), or interact with internal APIs that rely on implicit trust. This represents a significant risk for organizations hosting JeecgBoot in environments with sensitive internal network segments or cloud-native infrastructure.

## Recommendation

* Deploy the provided Sigma rule to detect attempts to reach the vulnerable endpoint.
* Implement strict firewall or web application firewall (WAF) rules to restrict access to the /airag/chat/send endpoint if it is not required for business operations.
* Monitor server access logs for anomalous outbound HTTP requests originating from the JeecgBoot server process.
* Upgrade JeecgBoot to the latest version once a fix is released.
