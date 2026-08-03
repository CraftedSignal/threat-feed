---
title: Deserialization Vulnerability in eta-otp-lock
slug: 2026-08-eta-otp-deserialization
description: An insecure deserialization vulnerability in TUBITAK BILGEM eta-otp-lock (CVE-2026-18642) allows unauthenticated attackers to perform object injection, potentially leading to remote code execution.
date: "2026-08-03T16:05:03Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - TUBITAK BILGEM Software Technologies Research Institute
products:
  - eta-otp-lock
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Deserialization of untrusted data vulnerability in TUBITAK BILGEM Software Technologies Research Institute eta-otp-lock allows Object Injection.
    confidence_band: high
cves:
  - id: CVE-2026-18642
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18642
  - https://siberguvenlik.gov.tr/guvenlik-bildirimleri/detay/tr-26-0730
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade eta-otp-lock to 1.0.4 or later
      owner: IT Operations
      due: 48h
      evidence: Vendor advisory indicates versions before 1.0.4 are affected.
---

The TUBITAK BILGEM Software Technologies Research Institute has disclosed a deserialization of untrusted data vulnerability (CVE-2026-18642) affecting the eta-otp-lock utility. This vulnerability, identified as CWE-502, resides in the way the application handles serialized objects. Successful exploitation allows an attacker to inject arbitrary objects into the application, which may facilitate unauthorized code execution or system compromise. The vulnerability affects all versions of eta-otp-lock prior to 1.0.4. Given the nature of object injection vulnerabilities, organizations utilizing this software should prioritize upgrading to version 1.0.4 or later to mitigate potential exploitation attempts.

## Impact

The vulnerability carries a CVSS 3.1 base score of 7.8, representing a high risk to the confidentiality, integrity, and availability of systems running vulnerable versions of eta-otp-lock. Successful exploitation could allow an attacker to achieve code execution with the privileges of the application process.

## Recommendation

- Upgrade the eta-otp-lock software to version 1.0.4 or later immediately.
- Review internal application logs for unauthorized object instantiation or unexpected process execution spawned by the eta-otp-lock service.
- Restrict network access to any instances of eta-otp-lock to ensure they are not exposed to untrusted sources, minimizing the potential for an attacker to send malicious serialized objects.
