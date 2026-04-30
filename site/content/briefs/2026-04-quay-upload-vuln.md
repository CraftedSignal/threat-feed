---
title: Red Hat Quay Image Upload Interference Vulnerability (CVE-2026-32589)
slug: 2026-04-quay-upload-vuln
description: CVE-2026-32589 describes a vulnerability in Red Hat Quay's container image upload process where an authenticated user can interfere with other users' uploads, potentially leading to unauthorized access and modification.
date: "2026-04-08T18:25:59Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - quay
  - image upload
  - vulnerability
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-32589
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32589
  - https://access.redhat.com/security/cve/CVE-2026-32589
  - https://bugzilla.redhat.com/show_bug.cgi?id=2446963
rules:
  - title: Detect Quay Image Upload Interference Attempt
    description: Detects potential attempts to interfere with Red Hat Quay image uploads by monitoring API requests that could modify image metadata or cancel uploads.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
  - title: Detect Quay Manifest Manipulation
    description: Detects attempts to manipulate container image manifests in Red Hat Quay, potentially indicating unauthorized modification.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - privilege_escalation
    techniques:
      - T1078
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-32589 identifies a flaw within the container image upload process of Red Hat Quay. An authenticated user, possessing push access to at least one repository within the Quay registry, can exploit this vulnerability to disrupt image uploads initiated by other users. The scope of this interference extends to uploads occurring in repositories where the attacker lacks explicit access privileges. This vulnerability allows a malicious actor to potentially read, modify, or even cancel another user's active image upload. This issue poses a significant risk to the integrity and confidentiality of container images stored within the registry, especially in multi-tenant environments.

## Attack Chain

1.  Attacker authenticates to the Red Hat Quay registry with valid credentials and push access to at least one repository.
2.  Attacker identifies an ongoing image upload by another user to a different repository.
3.  Attacker crafts a malicious request that exploits the vulnerability in the image upload process. This request targets the upload session of the victim user.
4.  The malicious request interferes with the victim's upload session, potentially by manipulating metadata or data chunks.
5.  If successful, the attacker gains the ability to read parts of the image being uploaded.
6.  The attacker can also modify the uploaded image, injecting malicious code or altering existing data.
7.  Alternatively, the attacker can cancel the image upload, preventing the victim user from completing the process.
8.  The compromised or incomplete image is then used by other users, leading to potential supply chain attacks or service disruptions.

## Impact

Successful exploitation of CVE-2026-32589 allows an attacker to compromise the integrity and confidentiality of container images stored within Red Hat Quay. This could lead to supply chain attacks, where malicious code is injected into container images and subsequently deployed across various systems. The impact includes potential data breaches, service disruptions, and unauthorized access to sensitive information. In multi-tenant environments, this vulnerability enables cross-tenant access, allowing attackers to compromise container images belonging to other organizations.

## Recommendation

*   Apply the patch or upgrade to the latest version of Red Hat Quay as recommended by Red Hat to address CVE-2026-32589 (https://access.redhat.com/security/cve/CVE-2026-32589).
*   Implement strict access control policies for Red Hat Quay repositories to minimize the potential impact of compromised accounts.
*   Deploy the Sigma rule provided below to monitor for suspicious activity related to image uploads and modifications on the Quay registry.
