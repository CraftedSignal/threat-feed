---
title: iDocView SSRF Vulnerability (CVE-2023-54402)
slug: 2026-09-idocview-ssrf
description: The iDocView /doc/upload endpoint is susceptible to unauthenticated server-side request forgery (SSRF), allowing remote attackers to read sensitive local files and scan internal network infrastructure.
date: "2026-09-30T22:37:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:idocview:idocview:*:*:*:*:*:*:*:*
vendors:
  - iDocView
products:
  - iDocView
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote unauthenticated attackers can bypass authentication using a hardcoded default token (testtoken) and exploit the endpoint to fetch arbitrary URLs.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Exploit the endpoint to fetch arbitrary URLs... to reach internal network hosts and services not otherwise accessible.
    confidence_band: high
cves:
  - id: CVE-2023-54402
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54402
rules:
  - title: Detects CVE-2023-54402 Exploitation - SSRF in iDocView via /doc/upload
    description: Detects exploitation attempts against the /doc/upload endpoint using the known bypass token 'testtoken' and signs of SSRF via file protocol.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1595
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Patch iDocView instances or apply WAF rules to block requests containing 'testtoken' to /doc/upload.
      owner: IT Operations
      due: 24h
      evidence: Source confirms bypass using 'testtoken'.
  hunt_leads:
    - lead: Search web logs for /doc/upload usage containing 'testtoken' or 'file://'.
      technique_id: T1190
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation observed by Shadowserver Foundation since 2024-03-26.
  mitigation_plan:
    - priority: immediate
      action: Verify current version of iDocView and ensure it is not vulnerable.
      owner: IT Operations
      addresses: CVE-2023-54402
      evidence: NVD vulnerability entry.
---

iDocView contains a critical server-side request forgery (SSRF) vulnerability identified as CVE-2023-54402. The vulnerability resides in the /doc/upload endpoint, where inadequate input validation permits remote unauthenticated attackers to supply a hardcoded default token, 'testtoken', to bypass authentication mechanisms. Once authenticated, the endpoint allows the retrieval of arbitrary URLs. Because the implementation lacks sufficient restriction on URL schemes, attackers can leverage file:// URIs to perform local file disclosure, potentially exposing sensitive operating system or application configuration files. Furthermore, the vulnerability enables attackers to perform internal reconnaissance by reaching network services that are typically isolated from external traffic. Exploitation of this vulnerability has been observed in the wild since at least March 26, 2024, as documented by the Shadowserver Foundation. Defenders should prioritize patching or restricting access to the affected endpoint to prevent unauthorized information disclosure and internal network pivot attempts.

## Attack Chain

1. Attacker identifies an internet-facing instance of iDocView hosting the vulnerable /doc/upload endpoint.
2. Attacker crafts an HTTP POST request targeting the /doc/upload endpoint.
3. Attacker includes the hardcoded value 'testtoken' in the request to bypass initial authentication requirements.
4. Attacker injects a target URL or URI into the request parameters to initiate the server-side request.
5. Attacker utilizes the file:// URI scheme to read sensitive system files (e.g., /etc/passwd or configuration files) from the application server.
6. Attacker utilizes HTTP/HTTPS URI schemes to probe internal network segments, services, or metadata endpoints not accessible from the public internet.
7. Attacker exfiltrates discovered internal host information or sensitive local file contents to an external listener.

## Impact

Successful exploitation of CVE-2023-54402 leads to unauthorized local file disclosure and the ability for an attacker to bypass network perimeter controls. By accessing internal services and configuration files, attackers can gain credentials, architectural insights, or administrative access to the underlying server and connected internal network, posing a significant risk to organizational confidentiality and infrastructure integrity.

## Recommendation

1. Restrict external network access to the iDocView /doc/upload endpoint if business requirements permit, or implement strict WAF filtering to intercept requests containing the 'testtoken' bypass value.
2. Deploy the provided Sigma rule to webserver logs to monitor for incoming HTTP requests targeting the /doc/upload endpoint with suspicious query parameters.
3. Monitor egress traffic from iDocView servers for anomalous network connections to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) or common cloud metadata services.
4. Audit application logs for evidence of access to the /doc/upload endpoint using the hardcoded 'testtoken' value.
