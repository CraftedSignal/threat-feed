---
title: Cleartext Credential Storage in Johnson Controls Simplex Incident Manager
slug: 2026-08-simplex-incident-manager
description: Johnson Controls Simplex Incident Manager versions 2.01 and earlier store sensitive user credentials in memory, allowing a local attacker with low privileges to extract them via memory analysis.
date: "2026-08-20T18:11:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Johnson Controls
products:
  - Simplex Incident Manager (2.01)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: This exposes sensitive information to potential extraction by anyone with local access to the system, including attackers leveraging memory-dumping tools or insiders with elevated privileges.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Simplex Incident Manager to version v2.01.01
      owner: IT Operations
      due: 72h
      evidence: Johnson Controls released a patched version (v2.01.01) to address this vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Restrict local access to servers running the application
      owner: IT Operations
      addresses: CVE-2026-27875
      evidence: Restrict local access to systems running the Simplex Incident Manager to authorized personnel only.
---

Johnson Controls has disclosed a vulnerability in the Simplex Incident Manager application, identified as CVE-2026-27875. The application insecurely stores user passwords and authentication tokens in cleartext within system memory during runtime. This vulnerability (CWE-316) impacts all versions of the product up to and including V2.01. An attacker who has achieved local access to the host system can leverage memory-dumping utilities or perform forensics on memory captures to retrieve these credentials. Given the role of Simplex Incident Manager in managing building automation and incident response, compromised credentials could lead to unauthorized access to the broader building automation infrastructure. Successful exploitation requires an attacker to already possess local access to the system with low-level privileges, and the exploitation has a high attack complexity rating.

## Impact

Successful exploitation of CVE-2026-27875 enables a local attacker to extract high-value credentials, potentially bypassing authentication to gain administrative control over the Simplex Incident Manager application. The impact is significant for organizations across the critical infrastructure sectors, including manufacturing, energy, and transportation, as unauthorized access could result in manipulation of safety and security systems. No exploitation has been reported in the wild.

## Recommendation

- Upgrade Simplex Incident Manager to version v2.01.01 or later to remediate CVE-2026-27875.
- Restrict local interactive access to servers running Simplex Incident Manager to authorized personnel only to prevent the execution of memory-scraping tools.
- Implement and enforce the principle of least privilege on host operating systems to prevent local users from performing unauthorized process memory dumps.
- Deploy endpoint protection solutions configured to detect and block known memory-dumping utilities (e.g., Mimikatz, Procdump, or custom memory-scraping scripts).
- Enable full-disk encryption and secure boot to mitigate risks associated with physical access and offline memory analysis.
