---
title: Arbitrary Code Execution in HashiCorp Vault via Plugin Catalog
slug: 2026-10-hashicorp-vault-ace
description: HashiCorp Vault is vulnerable to arbitrary code execution when restoring Raft snapshots containing malicious plugin catalog entries.
date: "2026-10-08T19:43:08Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - hashicorp
vendors:
  - HashiCorp
products:
  - Vault Community Edition (< 2.1.2)
  - Vault Enterprise (< 1.19.23, < 1.20.17, < 1.21.12, < 2.1.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The vulnerability allows an attacker to execute malicious code within the Vault environment by leveraging specifically crafted entries in the plugin catalog.
    confidence_band: high
references:
  - https://cyber.gc.ca/en/alerts-advisories/hashicorp-security-advisory-av26-1019
  - https://discuss.hashicorp.com/t/hcsec-2026-41-vault-vulnerable-to-arbitrary-code-execution-via-plugin-catalog-entries-restored-from-raft-snapshots/77813
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade Vault Community Edition to 2.1.2 or Vault Enterprise to respective fixed version (1.19.23, 1.20.17, 1.21.12, 2.1.2)
      owner: IT Operations
      addresses: HCSEC-2026-41
      evidence: Source advisory recommends applying updates as they become available
---

HashiCorp has released a security advisory regarding an arbitrary code execution (ACE) vulnerability in Vault Community Edition and Vault Enterprise (HCSEC-2026-41). The vulnerability occurs during the processing of plugin catalog entries that are restored from Raft snapshots. An attacker with sufficient privileges to modify the plugin catalog or supply a compromised Raft snapshot can introduce malicious entries, which are subsequently executed by the Vault process during restoration or startup. This allows an attacker to achieve code execution within the context of the Vault service, potentially compromising secrets, encryption keys, and the integrity of the entire Vault cluster. The issue affects Vault Community Edition versions prior to 2.1.2 and specific Vault Enterprise version branches (1.19.23, 1.20.17, 1.21.12, and 2.1.2).

## Impact

Successful exploitation allows an attacker to gain arbitrary code execution on the Vault server, which is typically a high-value asset in infrastructure environments. Compromise of Vault leads to the exposure of stored secrets, certificates, and credentials, impacting the security posture of all systems relying on Vault for identity or secret management.

## Recommendation

* Apply the security updates for HashiCorp Vault immediately to the recommended versions: Vault Community Edition 2.1.2 or later, and Vault Enterprise 1.19.23, 1.20.17, 1.21.12, or 2.1.2 and later.
* Audit access controls to the Raft snapshot management interfaces and plugin catalog configuration to ensure only authorized entities can perform modifications.
* Restrict access to administrative APIs that allow triggering Raft snapshot restoration.
