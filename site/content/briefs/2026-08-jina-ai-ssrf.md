---
title: CVE-2026-82638 - SSRF Vulnerability in Jina AI Reader
slug: 2026-08-jina-ai-ssrf
description: Jina AI reader contains a server-side request forgery vulnerability caused by a missing private-address guard when deployed outside of Google Cloud, allowing unauthenticated attackers to access internal network resources.
date: "2026-08-30T15:11:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jina:reader:*:*:*:*:*:*:*:*
vendors:
  - Jina AI
products:
  - reader
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This flaw allows unauthenticated attackers to bypass security controls and reach internal network services or metadata endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-82638
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82638
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all deployments of Jina AI reader and identify those running outside of Google Cloud.
      owner: IT Operations
      due: 48h
      evidence: The vulnerability only occurs outside of Google Cloud deployments.
  mitigation_plan:
    - priority: immediate
      action: Apply the vendor-provided patch or upgrade Jina AI reader to the secure version.
      owner: IT Operations
      addresses: CVE-2026-82638
---

CVE-2026-82638 is a critical server-side request forgery (SSRF) vulnerability affecting Jina AI reader. The vulnerability stems from the implementation logic of the internal request validator, which disables the private-address guard mechanism when the application detects it is not running within a Google Cloud environment. This misconfiguration allows unauthenticated actors to bypass intended network restrictions by supplying crafted, publicly resolvable hostnames that point to internal IP addresses or cloud metadata service endpoints (e.g., 169.254.169.254). An attacker can leverage this flaw to interact with internal services that lack authentication, potentially leading to unauthorized data exfiltration or internal service manipulation. Organizations deploying Jina AI reader in on-premises or non-GCP cloud environments are at the highest risk.

## Impact

Successful exploitation allows unauthenticated attackers to probe internal networks, retrieve sensitive cloud metadata, and access private services that are not exposed to the public internet. This bypasses network-level security controls, potentially leading to the compromise of internal credentials, environment configurations, or sensitive business data.

## Recommendation

Prioritize patching or updating Jina AI reader to a version that enforces the private-address guard regardless of the hosting environment. For environments where patching is not immediately feasible, implement egress filtering at the network boundary to prevent the application host from initiating connections to private address spaces (e.g., RFC1918) or sensitive metadata services. Ensure logs are reviewed for anomalous outbound requests originating from the application server that reference non-public or internal address schemes.
