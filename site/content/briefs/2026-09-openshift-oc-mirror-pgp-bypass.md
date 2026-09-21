---
title: CVE-2026-75939 - Signature Verification Bypass in Red Hat oc-mirror
slug: 2026-09-openshift-oc-mirror-pgp-bypass
description: A logic flaw in the oc-mirror tool allows remote attackers to bypass PGP signature verification, enabling the injection of malicious release payloads into disconnected registries.
date: "2026-09-21T16:29:19Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:red_hat:oc_mirror:*:*:*:*:*:*:*:*
tags:
  - supply-chain-security
  - cloud
  - red-hat
  - openshift
vendors:
  - Red Hat
products:
  - oc-mirror
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: A remote attacker, by intercepting or manipulating network traffic to the signature endpoint, could exploit this to craft a PGP message with a valid Red Hat release key ID but a forged signature.
    confidence_band: high
cves:
  - id: CVE-2026-75939
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75939
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch oc-mirror to the latest version provided by Red Hat to remediate CVE-2026-75939
      owner: IT Operations
      due: 48h
      evidence: Source confirms a logic flaw in existing versions
  mitigation_plan:
    - priority: immediate
      action: Enforce strict TLS/SSL inspection on networks used for image mirroring to prevent MITM manipulation
      owner: Network Security
      addresses: CVE-2026-75939
      evidence: Source identifies interception of network traffic as the primary attack vector
---

CVE-2026-75939 involves a critical logic vulnerability in the `oc-mirror` tool, which is used to manage disconnected OpenShift environments. The tool incorrectly verifies PGP release image signatures by executing signature error checks before the entire signed body is fully processed. This premature validation allows a remote attacker, capable of intercepting or manipulating network traffic (e.g., via Man-in-the-Middle techniques), to present a PGP message that contains a valid Red Hat release key ID but a forged signature body. Because the tool fails to validate the entire payload, it accepts the tampered release as legitimate. This vulnerability significantly impacts the software supply chain integrity by allowing the mirroring of malicious container images into internal, disconnected enterprise registries, where they may later be deployed into production clusters.

## Impact

The vulnerability allows for the unauthorized injection of malicious software components into isolated container registries. If exploited, an attacker can compromise the integrity of software deployments within an organization's internal infrastructure, potentially leading to arbitrary code execution across clusters that rely on the compromised mirror as a trusted source of truth.

## Recommendation

- Monitor for unauthorized or unexpected modifications to release image signatures or payloads being mirrored into disconnected registries.
- Implement and enforce strict TLS validation for all network connections involved in the image mirroring process to mitigate potential interception of signature endpoints.
- Patch the `oc-mirror` tool immediately once an official update is provided by Red Hat to address the signature verification logic flaw.
- Audit internal container registry logs for image layers that originated from unexpected network sources or that lack valid, verifiable cryptographic signatures.
