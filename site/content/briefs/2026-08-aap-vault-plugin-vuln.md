---
title: Credential Exfiltration via AAP Controller Vault Plugin
slug: 2026-08-aap-vault-plugin-vuln
description: A vulnerability in the Red Hat Ansible Automation Platform controller allows authenticated attackers to exfiltrate Kubernetes service account tokens via the HashiCorp Vault credential plugin.
date: "2026-08-18T16:55:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - exfiltration
  - vulnerability
vendors:
  - Red Hat
products:
  - Ansible Automation Platform
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The kubernetes_auth() function in awx_plugins/credentials/hashivault.py reads the controller pod's Kubernetes service account token and sends it to an attacker-controlled URL when a HashiCorp Vault Secret Lookup credential with kubernetes_role authentication is tested.
    confidence_band: high
cves:
  - id: CVE-2026-12564
    cvss: 9.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-12564
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch AAP Controller to address CVE-2026-12564
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-12564 documentation
  mitigation_plan:
    - priority: immediate
      action: Restrict credential-creation permissions in AAP to minimize attack surface
      owner: IT Operations
      addresses: CVE-2026-12564
      evidence: Source documentation of required privileges
---

A critical vulnerability (CVE-2026-12564) exists within the HashiCorp Vault credential plugin of the Red Hat Ansible Automation Platform (AAP) controller. Specifically, the kubernetes_auth() function within awx_plugins/credentials/hashivault.py contains a flaw that handles Kubernetes service account tokens insecurely. When a user tests a HashiCorp Vault Secret Lookup credential configured with kubernetes_role authentication, the plugin reads the controller pod's Kubernetes service account token and transmits it to an attacker-specified URL.

An authenticated attacker possessing credential-creation privileges can exploit this behavior to perform unauthorized token exfiltration. Successful exploitation grants the attacker Kubernetes API access to control plane namespaces. This level of access enables full pod CRUD operations and unauthorized reading of stored secrets, including database credentials and the Django SECRET_KEY, potentially leading to a complete compromise of the automation controller environment.

## Impact

Successful exploitation results in the exfiltration of the Kubernetes service account token associated with the AAP controller pod. With this token, an attacker can authenticate to the Kubernetes API server, gaining escalated privileges within the cluster. Impacted organizations face potential exposure of sensitive secrets, database credentials, and the application's SECRET_KEY, which are essential for maintaining the integrity and security of the automation platform and its managed infrastructure.

## Recommendation

- Immediately audit the Ansible Automation Platform controller configuration to restrict credential-creation privileges to trusted users only.
- Apply the vendor-provided patch for CVE-2026-12564 across all AAP controller instances.
- Review Kubernetes audit logs for anomalous outgoing connections originating from the AAP controller pods to unknown or suspicious external endpoints.
- Revoke and rotate any secrets, including database credentials and Django keys, that may have been accessible to the controller pod's service account if exploitation is suspected.
