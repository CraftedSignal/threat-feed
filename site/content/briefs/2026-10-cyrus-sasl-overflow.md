---
title: Heap-based Buffer Overflow in Cyrus SASL DIGEST-MD5 Plugin
slug: 2026-10-cyrus-sasl-overflow
description: A heap-based buffer overflow in the Cyrus SASL DIGEST-MD5 plugin, tracked as CVE-2026-107161, allows remote malicious servers to cause memory corruption in client applications.
date: "2026-10-07T20:45:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cyrus_sasl_project:cyrus_sasl:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
vendors:
  - Cyrus SASL
products:
  - Cyrus SASL
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A malicious or on-path DIGEST-MD5 (or HTTP Digest) server can trigger this flaw in a connecting client by supplying a crafted challenge field.
    confidence_band: high
cves:
  - id: CVE-2026-107161
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107161
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review application inventory for software utilizing Cyrus SASL for authentication.
      owner: IT Operations
      due: 48h
      evidence: The flaw resides in the add_to_challenge() function within the DIGEST-MD5 plugin.
  mitigation_plan:
    - priority: immediate
      action: Monitor for and apply security updates to Cyrus SASL once released.
      owner: IT Operations
      addresses: CVE-2026-107161
      evidence: NVD vulnerability disclosure.
---

CVE-2026-107161 identifies a critical heap-based buffer overflow vulnerability within the Cyrus SASL library, specifically affecting the DIGEST-MD5 plugin. The flaw resides in the add_to_challenge() function, which incorrectly calculates the required buffer size for challenge/response fields. The calculation occurs prior to the application of DIGEST-MD5 quoting, which escapes special characters and expands the string length. Consequently, the library allocates an insufficient buffer, which is subsequently passed to strcat(), resulting in a heap-based out-of-bounds write.

The vulnerability is triggered when a client application, utilizing the affected version of Cyrus SASL, connects to a malicious or compromised server that sends a crafted challenge field (e.g., realm or nonce). The resulting memory corruption typically causes the client application to crash, though the primitive may support arbitrary code execution in specific environments. Because the vulnerability exists within the client-side parsing logic, any application linking against the vulnerable version of Cyrus SASL for authentication is potentially at risk.

## Impact

Successful exploitation of this vulnerability leads to a denial of service through application crashes. Given the nature of the heap-based buffer overflow, there is a risk of arbitrary code execution, which could allow an attacker to compromise the host system running the client-side software. This vulnerability affects any environment using Cyrus SASL for authentication, including enterprise mail servers, directory services, and various network client tools.

## Recommendation

Detection and mitigation should focus on upgrading the library and monitoring for application instability.

- Upgrade the Cyrus SASL library to the patched version once released by the vendor or package maintainer.
- Monitor application logs and system event logs (such as Windows Event Viewer or Linux systemd journal) for frequent crash dumps (SIGSEGV or access violations) originating from services utilizing Cyrus SASL.
- Audit client-side network connections to verify that they are connecting only to known-trusted and authenticated servers to mitigate the risk of a malicious server triggering the flaw.
