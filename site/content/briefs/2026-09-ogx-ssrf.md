---
title: Unauthenticated Server-Side Request Forgery in OGX
slug: 2026-09-ogx-ssrf
description: OGX contains an unauthenticated Server-Side Request Forgery vulnerability in the POST /v1/responses endpoint, allowing remote attackers to probe internal cloud metadata services.
date: "2026-09-04T15:28:55Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ogx:ogx:*:*:*:*:*:*:*:*
vendors:
  - OGX
products:
  - OGX (commit <= fbe8e0f)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can supply a malicious server_url parameter via MCP tool definitions to force the server to initiate requests to arbitrary internal resources.
    confidence_band: high
cves:
  - id: CVE-2026-85666
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85666
rules:
  - title: Detects CVE-2026-85666 Exploitation - SSRF via /v1/responses
    description: Detects HTTP POST requests to the /v1/responses endpoint containing sensitive cloud metadata addresses in the server_url parameter.
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
    - action: Patch OGX to latest version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-85666 advisory
    - action: Deploy Sigma detection for SSRF patterns
      owner: Detection Engineering
      due: 24h
      evidence: Rule defined in brief
  mitigation_plan:
    - priority: immediate
      action: Egress firewall filtering
      owner: IT Operations
      addresses: CVE-2026-85666
      evidence: High risk of cloud metadata exfiltration
---

OGX (formerly Llama Stack), up to commit fbe8e0f, contains a critical server-side request forgery (SSRF) vulnerability in its OpenAI-compatible POST /v1/responses endpoint. The vulnerability stems from the MCP tool definition processing logic, where the server_url parameter is fetched server-side without performing necessary destination validation. Specifically, the validate_url_not_private() guard, which is correctly implemented for other input fields, is omitted for the server_url parameter. 

In default configurations that lack authentication, a remote, unauthenticated attacker can exploit this flaw to force the OGX server to initiate connections to arbitrary internal network resources. This includes sensitive cloud metadata endpoints such as 169.254.169.254. Furthermore, the vulnerability allows for the forwarding of attacker-supplied headers and bearer tokens to these internal destinations, potentially leading to unauthorized data exfiltration or internal system interaction. This vulnerability represents a high risk for deployments residing in cloud environments where metadata services contain IAM credentials or sensitive configuration information.

## Impact

Successful exploitation allows unauthenticated remote attackers to bypass network perimeters and interact with internal-only services. In cloud-native deployments, this typically results in the exfiltration of sensitive cloud metadata (e.g., IAM role credentials, instance metadata), which can be leveraged for lateral movement or full compromise of the cloud account.

## Recommendation

- Immediately update all OGX instances to a version beyond commit fbe8e0f.
- Implement strict network egress filtering on all servers hosting the OGX platform to prevent connections to internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and 169.254.169.254).
- Deploy the Sigma rule below to detect abnormal POST requests to the affected endpoint.
- Apply the following Sigma rule to your webserver access logs to identify exploitation attempts targeting the v1/responses endpoint.
