---
title: Improper Certificate Validation in SWUpdate
slug: 2026-10-swupdate-cert-validation
description: SWUpdate through 2026.05.1 is vulnerable to certificate validation bypass in crypto/swupdate_cms_verify_openssl.c, allowing attackers to sign and install malicious update packages.
date: "2026-10-12T18:34:05Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:swupdate:swupdate:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - firmware-security
  - supply-chain
vendors:
  - SWUpdate
products:
  - SWUpdate (<= 2026.05.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195.002
    technique_name: 'Supply Chain Compromise: Compromise Software Dependencies'
    evidence: Attackers holding a signing key from a sibling intermediate under the same root can embed that intermediate in the signature to install malicious updates.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.002
    technique_name: 'User Execution: Malicious File'
    evidence: This flaw allows an attacker... to craft malicious updates by embedding the intermediate certificate into the CMS SignedData.
    confidence_band: high
cves:
  - id: CVE-2026-109399
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109399
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all instances of SWUpdate to a version beyond 2026.05.1
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-109399 vulnerability affects versions up to 2026.05.1
  mitigation_plan:
    - priority: immediate
      action: Upgrade SWUpdate to a patched version
      owner: IT Operations
      addresses: CVE-2026-109399
      evidence: NVD vulnerability disclosure
---

SWUpdate, an update agent for embedded Linux devices, contains a critical vulnerability (CVE-2026-109399) within the crypto/swupdate_cms_verify_openssl.c source file. The vulnerability arises from improper certificate validation during the verification of CMS SignedData. Specifically, the implementation erroneously trusts untrusted X.509 certificates that are embedded directly within the signature for the purpose of chain building.

This flaw allows an attacker who possesses a valid signing key from a sibling intermediate certificate (issued by the same root CA as the legitimate update server) to craft a malicious update package. By embedding the compromised sibling intermediate certificate into the CMS SignedData, the attacker can force the SWUpdate verification logic to accept the malicious package as authentic. This allows the delivery and installation of arbitrary, potentially malicious update binaries on the target embedded device. Organizations using SWUpdate to manage remote firmware updates should prioritize patching or implementing strict signature verification controls.
