---
title: Unauthenticated SSRF in SeaweedFS VolumeServer.FetchAndWriteNeedle
slug: 2026-08-seaweedfs-ssrf
description: SeaweedFS versions prior to 4.24 are vulnerable to unauthenticated SSRF via the VolumeServer.FetchAndWriteNeedle RPC, allowing attackers to access internal services and cloud metadata endpoints.
date: "2026-08-11T17:48:34Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - SeaweedFS
products:
  - SeaweedFS (< 4.24)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker able to reach a volume server's gRPC port could coerce the server into issuing requests to arbitrary hosts.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1595
    technique_name: Active Scanning
    evidence: This allows for the exfiltration of instance IAM credentials and can be used to reach otherwise-unexposed internal services.
    confidence_band: high
cves:
  - id: CVE-2026-73080
    cvss: 9.3
references:
  - https://github.com/advisories/GHSA-87fv-vqqr-m4jr
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73080
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch SeaweedFS to version 4.24 or higher
      owner: IT Operations
      due: 24h
      evidence: Fixed in 4.24.
  mitigation_plan:
    - priority: immediate
      action: Restrict gRPC port access via network firewall
      owner: IT Operations
      addresses: CVE-2026-73080
      evidence: Restrict volume server gRPC ports to trusted hosts via firewall / network policy.
---

SeaweedFS versions prior to 4.24 contain an unauthenticated Server-Side Request Forgery (SSRF) vulnerability within the VolumeServer.FetchAndWriteNeedle RPC endpoint. This endpoint, intended to fetch and write data into a needle, performs no authentication and lacks validation of the requested target host. An attacker with network access to the gRPC port can coerce the volume server to issue requests to arbitrary targets, including loopback addresses, RFC 1918 private IP ranges, and cloud metadata services (e.g., 169.254.169.254).

The flaw is significant because the vulnerability persists even if standard JWT signing keys are configured for other administrative operations. In cloud-hosted deployments, this vulnerability facilitates the exfiltration of instance IAM credentials and allows for interaction with otherwise unexposed internal infrastructure. Attackers can read the response back from these targets, enabling complete information disclosure. The vulnerability was patched in version 4.24 by introducing mandatory admin authorization and a guarded dialer that restricts target IP ranges and prevents DNS-rebinding.

## Impact

Successful exploitation allows for the exfiltration of sensitive cloud instance metadata, including IAM tokens, and unauthorized interaction with internal services restricted by network boundaries. This affects all SeaweedFS deployments, particularly those hosted in cloud environments (AWS, GCP, Azure) where the metadata service is reachable. The vulnerability requires network access to the volume server's gRPC plane, which is unauthenticated by default.

## Recommendation

* Update all SeaweedFS instances to version 4.24 or later immediately to patch CVE-2026-73080.
* Implement network-level access control to restrict access to the SeaweedFS gRPC ports (default port 8080) to trusted IP addresses only, blocking direct internet exposure.
* Enable mTLS via `security.toml` to enforce transport layer authentication for all gRPC communication.
* Audit VPC flow logs or network logs for anomalous outbound connections originating from SeaweedFS volume servers to internal infrastructure or known cloud metadata endpoints.
