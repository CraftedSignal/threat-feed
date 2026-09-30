---
title: CRI-O Sandbox State Persistence Trust-Boundary Vulnerability
slug: 2026-09-crio-sandbox-escape
description: A trust-boundary vulnerability in CRI-O allows an attacker to manipulate pod metadata to overwrite sandbox bookkeeping, enabling container escape via host-side resource mounting upon container recreation.
date: "2026-09-30T12:34:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kubernetes:cri-o:*:*:*:*:*:*:*:*
tags:
  - container-security
  - privilege-escalation
  - runtime-security
vendors:
  - Kubernetes
products:
  - CRI-O
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: a later container recreate in that sandbox can expose a host-side runtime-management resource inside the container, enabling container escape.
    confidence_band: high
cves:
  - id: CVE-2026-62146
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62146
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Monitor vendor channels for the release of the patched CRI-O version addressing CVE-2026-62146.
      owner: IT Operations
      due: 72h
      evidence: NVD advisory for CVE-2026-62146
  mitigation_plan:
    - priority: immediate
      action: Upgrade CRI-O runtime as soon as the patch is released.
      owner: IT Operations
      addresses: CVE-2026-62146
      evidence: Trust-boundary vulnerability in sandbox state persistence
---

CVE-2026-62146 describes a critical trust-boundary flaw within the CRI-O container runtime related to its sandbox state persistence mechanism. An attacker capable of influencing pod metadata can overwrite CRI-O's internally reserved sandbox bookkeeping information. This state is serialized and subsequently treated as trusted by the runtime upon a process restart or daemon reload. When the affected sandbox is triggered to recreate a container, the compromised state data directs the runtime to inadvertently mount sensitive host-side runtime-management resources directly into the container filesystem. This transition from untrusted pod input to trusted runtime configuration facilitates a container escape, granting the attacker access to host-level resources and providing a pathway for privilege escalation. This vulnerability poses a significant risk in multi-tenant environments where pod metadata may be partially accessible or influenced by non-privileged users.

## Impact

Successful exploitation of CVE-2026-62146 allows an attacker to break out of the container isolation boundary. By accessing host-side runtime management resources, an attacker can achieve full host compromise, potentially leading to unauthorized data access, lateral movement within the cluster, and persistent control over the underlying node. This vulnerability affects all environments running vulnerable versions of CRI-O.

## Recommendation

- Update the CRI-O runtime to the latest patched version once released by the vendor to address the sandbox state persistence flaw.
- Audit Kubernetes pod specifications to ensure that metadata fields are restricted and cannot be manipulated by untrusted users or processes.
- Monitor node-level logs for unusual container lifecycle events, such as repeated unexpected container recreations or initialization patterns associated with unauthorized configuration changes.
