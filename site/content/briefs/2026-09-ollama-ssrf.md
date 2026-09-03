---
title: Ollama Arbitrary Redirect Vulnerability (CVE-2026-85180)
slug: 2026-09-ollama-ssrf
description: Ollama versions fail to validate redirect destinations during model pulls, allowing unauthenticated attackers to perform Server-Side Request Forgery (SSRF) against internal resources and cloud metadata services.
date: "2026-09-03T15:22:09Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ssrf
  - cloud-security
vendors:
  - Ollama
products:
  - Ollama
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can control a registry, serve a malicious tensor-layer manifest, and cause the server to issue GET requests to internal hosts.
    confidence_band: high
cves:
  - id: CVE-2026-85180
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85180
action_plan:
  priority: elevated
  owners:
    - SOC
    - Infrastructure Security
  immediate_actions:
    - action: Restrict Ollama egress traffic to only trusted model registry domains
      owner: Infrastructure Security
      due: 24h
      evidence: CVE-2026-85180 allows arbitrary redirects to internal hosts
  hunt_leads:
    - lead: Ollama process initiating connections to 169.254.169.254
      technique_id: T1190
      data_needed:
        - Network connection logs (Firewall/VPC Flow Logs)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: CVE-2026-85180 allows SSRF targeting cloud metadata endpoints
  mitigation_plan:
    - priority: immediate
      action: Upgrade to patched Ollama version once released
      owner: IT Operations
      addresses: CVE-2026-85180
      evidence: CVE-2026-85180 identified as the vulnerability source
---

CVE-2026-85180 describes a critical security flaw in Ollama involving improper validation of redirect destinations during the retrieval of tensor-layer models. An unauthenticated attacker can host a malicious registry that provides a crafted tensor-layer manifest. When an Ollama instance attempts to pull a model from this registry, the server follows HTTP redirects provided by the attacker, leading to unauthorized GET requests. This vulnerability enables Server-Side Request Forgery (SSRF), which can be exploited to probe internal network services or access sensitive cloud metadata endpoints. This is particularly dangerous in cloud-hosted environments where metadata services (like 169.254.169.254) are reachable from the Ollama host, potentially exposing instance identity tokens or environment configuration. Defenders should treat all model pull requests from untrusted registries as a high-risk activity.

## Impact

Successful exploitation of CVE-2026-85180 allows attackers to perform internal network reconnaissance and potentially exfiltrate sensitive credentials or configuration data from cloud metadata services. This risk is elevated in environments where Ollama instances have network access to internal resources or cloud management interfaces.

## Recommendation

- Monitor for outgoing HTTP GET requests initiated by the Ollama process toward internal IP ranges (e.g., 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and specifically the cloud metadata endpoint (169.254.169.254).
- Restrict the Ollama server's network access to known-trusted external registries only, using firewall egress rules to block communication with unverified model repositories.
- Patch Ollama installations immediately once an update addressing CVE-2026-85180 is released by the vendor.
- Review network logs for the Ollama binary for unusual connections to non-registry destinations or internal hosts.
