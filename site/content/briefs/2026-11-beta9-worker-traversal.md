---
brief_id: brief-2026-11-01-beta9-worker-traversal
event_id: brief-2026-11-01-beta9-worker-traversal
revision: 1
activity_at: "2026-11-01T14:53:54Z"
title: 'Beta9 Worker: Sandbox path traversal (CVE-2026-120307)'
slug: 2026-11-beta9-worker-traversal
description: The Beta9 worker contains a path traversal vulnerability in the sandbox file API that allows authenticated tenants to read, write, and delete arbitrary files on the host worker filesystem.
date: "2026-11-01T14:53:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-supported details require internal environment validation of worker configurations
cpes:
  - cpe:2.3:a:beta9:worker:*:*:*:*:*:*:*:*
vendors:
  - Beta9
products:
  - worker (< 0.1.756)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A tenant with a workspace token and one running sandbox can read, write, list, and delete files on the hosting worker as root, including files of other tenants on that machine.
    confidence_band: high
cves:
  - id: CVE-2026-120307
    cvss: 9.9
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120307
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Beta9 worker to 0.1.756
      owner: IT Operations
      due: 24h
      evidence: Fixed in worker 0.1.756
  hunt_leads:
    - lead: Identify requests to the sandbox file API containing parent-directory traversal patterns
      technique_id: T1068
      data_needed:
        - Application-level access logs for sandbox file API (e.g., path parameters)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: If the unresolved path starts with a mount destination... the remainder is joined onto that mount's source with filepath.Join... A long enough run of those segments names any absolute path on the worker.
  mitigation_plan:
    - priority: immediate
      action: Restrict Kubernetes service account permissions for worker pods
      owner: IT Operations
      addresses: Cluster-wide compromise risk
      evidence: In the shipped remote-node manifests that service account is bound to cluster-admin.
---

Beta9 worker versions prior to 0.1.756 are vulnerable to a path traversal flaw in the sandbox file API due to improper sanitization in the getHostPathFromContainerPath function. Attackers with a valid workspace token and an active sandbox can perform unauthorized file operations on the host worker filesystem. This access can be used to read or modify data belonging to other tenants and, in cases where the worker pod is assigned cluster-admin permissions, can lead to full cluster compromise. The vulnerability is confirmed to allow reading the Kubernetes service account token.

## Attack Chain

1. Attacker gains access to a valid tenant workspace token.
2. Attacker initiates or uses an active sandbox session.
3. Attacker crafts a file path containing sequences that bypass the mount destination prefix check.
4. The getHostPathFromContainerPath function resolves the malicious path to an absolute path on the host worker filesystem.
5. The file API calls (Upload, download, stat, list, find-in-files, replace-in-files, or delete-file) interact with the resolved host path.
6. The attacker reads or modifies sensitive host files, such as the Kubernetes service account token.
7. If applicable, the attacker uses the stolen service account token to achieve cluster-admin access.

## Impact

An attacker can achieve full read, write, and delete access to the host worker filesystem as root. This allows for the exfiltration of data from other tenants on the same worker and potential cluster-wide privilege escalation if the worker pod is configured with elevated Kubernetes permissions.

## Recommendation

- Upgrade the Beta9 worker to version 0.1.756 or later immediately to implement os.OpenRoot for sandbox file operations.
- Audit Kubernetes RBAC configurations for worker pods to ensure the principle of least privilege is applied, specifically restricting cluster-admin access for worker pods.
- Review access logs for the sandbox file API for anomalous path requests involving multiple parent-directory segments.
