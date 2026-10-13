---
title: Missing Authorization in Makunet maku-boot Configuration Endpoints
slug: 2026-10-makunet-maku-boot-auth-bypass
description: Makunet maku-boot versions 4.3.0 through 5.0.0 suffer from a missing authorization vulnerability, enabling authenticated users to exfiltrate cloud service credentials and send unauthorized emails.
date: "2026-10-13T18:37:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:makunet:maku-boot:4.3.0:*:*:*:*:*:*:*
  - cpe:2.3:a:makunet:maku-boot:5.0.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - cve
vendors:
  - Makunet
products:
  - maku-boot (4.3.0 through 5.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Makunet maku-boot 4.3.0 through 5.0.0 contains a missing authorization vulnerability that allows authenticated users to read mail and SMS configurations by calling /sys/mail/config/list and /sys/sms/config/list without the required authority checks.
    confidence_band: high
cves:
  - id: CVE-2026-110123
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110123
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade maku-boot to a patched version beyond 5.0.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-110123
    - action: Audit access logs for hits to /sys/mail/config/* or /sys/sms/config/*
      owner: SOC
      due: 24h
      evidence: NVD vulnerability detail
  mitigation_plan:
    - priority: immediate
      action: Rotate stored cloud access keys and SMTP passwords
      owner: IT Operations
      addresses: CVE-2026-110123
      evidence: Credential exposure documented in vulnerability report
---

Makunet maku-boot versions 4.3.0 through 5.0.0 contain a critical missing authorization vulnerability. The application fails to perform necessary authority checks on specific system configuration endpoints, specifically '/sys/mail/config/list' and '/sys/sms/config/list'. This oversight allows any authenticated user to interact with these sensitive API routes. 

By exploiting this flaw, an attacker can retrieve unmasked SMTP credentials and administrative access keys for major cloud service providers including Aliyun, Tencent Cloud, Qiniu, and Huawei Cloud. Furthermore, the vulnerability allows unauthorized access to the '/sys/mail/config/send' endpoint, which can be manipulated to trigger outbound mail to arbitrary recipients. This represents a significant risk for credential theft, lateral movement via cloud service abuse, and the facilitation of phishing or spam campaigns originating from the compromised host's mail infrastructure.

## Impact

The vulnerability poses a high risk to organizations utilizing maku-boot, specifically regarding the exposure of cloud service provider access keys and internal email infrastructure. Successful exploitation allows for the exfiltration of sensitive configuration data, enabling further compromise of associated cloud environments and the potential for mass unauthorized messaging. No specific victim counts have been reported, but the broad scope of affected cloud providers significantly increases the blast radius for affected enterprise users.

## Recommendation

* Immediately upgrade Makunet maku-boot to a version addressing this missing authorization vulnerability.
* Audit access logs for any requests directed to '/sys/mail/config/' or '/sys/sms/config/' endpoints to identify potential unauthorized reconnaissance or exploitation attempts.
* Rotate all SMTP credentials and cloud access keys (Aliyun, Tencent Cloud, Qiniu, Huawei Cloud) that were stored within the maku-boot configuration.
* Restrict network access to the application management interface to trusted administrative subnets only.
