---
title: 'CVE-2026-16487: Improper Container Signature Validation in bootc'
slug: 2026-10-bootc-signature-flaw
description: A vulnerability in bootc allows for the execution of arbitrary unsigned container content as the host root filesystem due to insecure default signature policies.
date: "2026-10-19T06:58:17Z"
lastmod: "2026-10-19T09:04:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:bootc:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - container-security
  - bootc
  - persistence
  - privilege-escalation
vendors:
  - Red Hat
products:
  - bootc
  - ostree
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: An attacker who can update that tag to execute arbitrary OS content as the host root filesystem on reboot.
    confidence_band: high
cves:
  - id: CVE-2026-16487
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16487
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16460
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Audit bootc registry configuration for insecureAcceptAnything settings
      owner: Security Engineering
      due: 48h
      evidence: CVE-2026-16487 advisory
  mitigation_plan:
    - priority: immediate
      action: Strictly define signature verification policies in /etc/containers/policy.json to disallow unsigned images
      owner: IT Operations
      addresses: CVE-2026-16487
      evidence: NVD vulnerability mitigation guidance
updates:
  - at: "2026-10-19T09:04:44Z"
    level: L2
    summary: added coverage for bootc +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-16460
---

CVE-2026-16487 describes a security vulnerability in bootc, an image-based operating system deployment tool. The flaw arises when bootc operates under the default containers signature policy. In this configuration, registries that fall through to the insecureAcceptAnything policy allow for the application of unsigned content during automatic or manual image tag updates. An attacker with the ability to modify or poison a mutable image tag on a registry can cause the host to pull and apply unauthorized, unsigned container images. Upon the next system reboot, this malicious content is executed as the host's root filesystem, granting the attacker persistent control with full administrative privileges over the affected system. This vulnerability poses a significant risk to the integrity of systems managed via image-based deployment, effectively turning a standard update process into a vector for full system compromise.

## Impact

Successful exploitation results in arbitrary code execution with root privileges on the host system. This allows for total system takeover, data exfiltration, and establishment of long-term persistence that survives standard reboots. The vulnerability affects environments using mutable tags for bootc image deployments without strictly configured signature verification policies.

## Recommendation

- Review and harden the container signature policy configuration to explicitly deny unsigned images, ensuring that registries do not fall through to insecureAcceptAnything.
- Monitor registry activity for unauthorized modifications to mutable image tags used for bootc deployments.
- Transition to immutable image tags (using digests rather than tags) for production deployments to mitigate the risk of tag poisoning.
- Monitor system logs for unexpected or unauthorized bootc update events that trigger image replacement.
