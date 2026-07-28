---
title: IBM Langflow OSS Vulnerability Allows FAISS Namespace Reuse and Information Disclosure (CVE-2026-13442)
slug: 2026-07-ibm-langflow-oss-faiss-namespace
description: A critical vulnerability, CVE-2026-13442, in IBM Langflow OSS versions 1.0.0 through 1.10.1 enables an authenticated attacker to reuse other users' FAISS namespaces, leading to cross-user information disclosure of owner-only vector content and potential limited integrity impact via persistent poisoning of query results.
date: "2026-07-28T21:23:41Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - information-disclosure
  - software-vulnerability
  - access-control-bypass
vendors:
  - IBM
products:
  - Langflow OSS 1.0.0
  - Langflow OSS 1.10.1
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: can allow an attacker to reuse another user's FAISS namespace
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: 'PR:L (Privileges Required: Low)'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: access owner-only vector content
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: can allow an attacker to reuse another user's FAISS namespace to access owner-only vector content and influence later query results.
    confidence_band: med
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1560
    technique_name: Data Manipulation
    evidence: limited integrity impact through persistent poisoning of returned results.
    confidence_band: med
cves:
  - id: CVE-2026-13442
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13442
  - https://www.ibm.com/support/pages/node/7279988
---

IBM Langflow OSS, specifically versions 1.0.0 up to and including 1.10.1, is affected by a high-severity vulnerability identified as CVE-2026-13442. This flaw allows an authenticated attacker with low privileges to bypass access controls within the application by reusing another user's FAISS (Facebook AI Similarity Search) namespace. The successful exploitation of this vulnerability results in unauthorized access to sensitive, owner-only vector content stored in the FAISS database, leading to cross-user information disclosure. Furthermore, the attacker can leverage this access to influence the results of future queries through persistent data poisoning, causing a limited integrity impact on the system. While no active exploitation has been reported, the vulnerability poses a significant risk to the confidentiality and integrity of data within affected Langflow OSS deployments.

## Attack Chain

1. An attacker obtains valid, low-privileged credentials to an IBM Langflow OSS instance, satisfying the "Privileges Required: Low" condition of CVE-2026-13442.
2. The attacker identifies a target user's FAISS namespace, which contains vector content intended to be exclusive to that user.
3. Leveraging CVE-2026-13442, the attacker crafts and sends a malicious request to the Langflow OSS application.
4. Due to the vulnerability, Langflow OSS incorrectly processes the request, allowing the attacker to associate with and operate within the target user's FAISS namespace.
5. The attacker then executes queries or retrieves data from the now-accessible FAISS namespace, gaining unauthorized access to owner-only vector content.
6. This unauthorized access results in the cross-user information disclosure of sensitive data.
7. The attacker may also submit manipulated data or configurations into the compromised namespace, causing persistent poisoning that influences the results of subsequent legitimate queries by the target user.
8. This persistent poisoning leads to a limited integrity impact on the application's functionality and the trustworthiness of its returned results.

## Impact

The successful exploitation of CVE-2026-13442 leads to severe consequences primarily related to data confidentiality and integrity. Attackers can gain unauthorized access to sensitive, owner-only vector content belonging to other users, resulting in cross-user information disclosure. This could expose proprietary data, user-specific insights, or other confidential information stored within the FAISS vector database. Additionally, the ability to "poison" returned query results introduces a limited integrity risk, potentially leading to incorrect data being presented to legitimate users, flawed decisions based on compromised information, or other forms of data manipulation that could impact the reliability of the Langflow OSS application.

## Recommendation

* Patch CVE-2026-13442 immediately by upgrading IBM Langflow OSS to a version greater than 1.10.1 as specified in the IBM support advisory.
* Monitor authentication logs for unusual login patterns or attempts to use valid credentials from unexpected sources, which could indicate the initial access step (T1078) for CVE-2026-13442 exploitation.
* Review network access logs for connections to Langflow OSS from suspicious IP addresses, as exploitation of CVE-2026-13442 occurs over the network (AV:N).
