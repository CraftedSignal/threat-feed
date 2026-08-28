---
title: Incus Authorization Bypass in Instance Copying (CVE-2026-55622)
slug: 2026-08-incus-bypass
description: An authorization bypass vulnerability in Incus allows unauthorized users to copy instances between projects if the source project and instance names are known, potentially leading to secret exfiltration.
date: "2026-08-28T21:14:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:linuxcontainers:incus:*:*:*:*:*:*:*:*
vendors:
  - Linux Containers
products:
  - Incus (< 7.2.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The issue could allow an attacker to access secrets in instances they are not authorized to access.
    confidence_band: high
cves:
  - id: CVE-2026-55622
    cvss: 7.7
    epss: 0.00201
references:
  - https://github.com/advisories/GHSA-c9f5-j9c3-mhrg
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55622
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Incus to version 7.2.0 or later across all clusters
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends version 7.2.0 to resolve CVE-2026-55622
  mitigation_plan:
    - priority: immediate
      action: Upgrade Incus to 7.2.0
      owner: IT Operations
      addresses: CVE-2026-55622
      evidence: Source advisory specifies 7.2.0 as the fixed version
---

Incus, a container and system virtual machine manager, contains a critical authorization bypass vulnerability (CVE-2026-55622) affecting the instance copying process. The flaw resides in `cmd/incusd/instances_post.go`, where the system fails to verify whether a caller has permission to access the source instance when performing an instance copy across projects. An attacker who is restricted to a specific project can exploit this by guessing or discovering the names of instances and projects they are not authorized to view. By providing these names in a copy request to the API, the attacker can instantiate a copy of the unauthorized instance within their own accessible project. This allows for the exfiltration of sensitive data, such as credentials or secrets stored within the hijacked instance. The vulnerability affects Incus versions prior to 7.2.0.

## Attack Chain

1. Attacker obtains initial access to the Incus API using restricted credentials.
2. Attacker probes for project and instance naming conventions to identify targets.
3. Attacker crafts a JSON payload for the `POST /1.0/instances` API endpoint.
4. Attacker populates the `source` field in the payload with the target project and instance names.
5. Attacker submits the POST request to the Incus controller.
6. The `incusd` service fails to validate permissions on the source instance, executing the copy operation.
7. Attacker accesses the copied instance in their project and retrieves sensitive data or secrets.
8. Attacker may migrate the newly copied instance to an external server to further obfuscate activity.

## Impact

Successful exploitation allows unauthorized access to data within private instances, potentially leading to widespread information disclosure. Organizations relying on project-based multi-tenancy are at risk of data leakage if internal naming schemes are predictable or discovered through reconnaissance.

## Recommendation

1. Upgrade Incus to version 7.2.0 or later immediately to patch CVE-2026-55622.
2. Audit existing Incus access control lists and certificate restrictions to identify overly permissive configurations.
3. Monitor API logs for unusual `POST /1.0/instances` activity, specifically looking for copy requests involving projects outside of expected user scopes.
4. Implement strict naming conventions for projects and instances to increase the difficulty of guessing targets.
