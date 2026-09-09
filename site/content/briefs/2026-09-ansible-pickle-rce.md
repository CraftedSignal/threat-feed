---
title: Remote Code Execution in Ansible community.general Memcached Plugin
slug: 2026-09-ansible-pickle-rce
description: An insecure deserialization vulnerability in the community.general Ansible collection's memcached cache plugin allows unauthenticated attackers to achieve remote code execution via pickle payload injection.
date: "2026-09-09T19:01:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ansible:community.general:*:*:*:*:*:*:*:*
vendors:
  - Ansible
products:
  - community.general
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Because memcached is unauthenticated and cache keys are predictable, an attacker able to reach a network-exposed or shared memcached instance can write a crafted pickle payload that is deserialized and executed on the Ansible controller.
    confidence_band: high
cves:
  - id: CVE-2026-87874
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-87874
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Restrict network access to memcached servers used by Ansible.
      owner: IT Operations
      due: 24h
      evidence: Memcached is unauthenticated; attacker requires network reachability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade community.general Ansible collection to the version addressing CVE-2026-87874.
      owner: IT Operations
      addresses: CVE-2026-87874
      evidence: NVD vulnerability disclosure.
---

The community.general Ansible collection contains a vulnerability in its memcached cache plugin that exposes Ansible controllers to remote code execution. Although the plugin documentation implies records are stored in JSON, it lacks explicit serialization, relying instead on python-memcached. This library defaults to pickling values during write operations and unpickling them upon retrieval. Because memcached instances frequently lack authentication and cache keys are often predictable, an attacker with network access to the memcached server can inject a crafted pickle payload. When the Ansible controller attempts to retrieve a fact from the poisoned cache, the deserialization process triggers arbitrary code execution. This vulnerability is critical in environments where memcached instances are shared or exposed to untrusted network segments.

## Impact

The vulnerability results in full remote code execution on the Ansible controller, potentially granting an attacker complete control over the automation environment. This allows for the manipulation of infrastructure, theft of secrets, and horizontal movement within the target network. The impact is significant for organizations relying on Ansible for large-scale configuration management.

## Recommendation

- Audit all Ansible controller configurations to identify usage of the memcached cache plugin.
- Implement strict network access control lists (ACLs) to ensure that memcached instances are not accessible from unauthorized segments or untrusted hosts.
- Upgrade the community.general Ansible collection to the latest patched version when available.
- Transition from unauthenticated memcached instances to configurations that enforce authentication or encryption if the environment allows.
