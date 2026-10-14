---
title: Information Disclosure Vulnerability in libssh
slug: 2026-10-libssh-info-disclosure
description: A vulnerability in libssh (CVE-2023-6004) allows a remote, authenticated attacker to disclose sensitive information due to improper handling of SSH agent forwarding requests.
date: "2026-10-14T16:28:07Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:libssh:libssh:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:38:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:8.0:*:*:*:*:*:*:*
  - cpe:2.3:o:redhat:enterprise_linux:9.0:*:*:*:*:*:*:*
vendors:
  - libssh
products:
  - libssh (< 0.10.6)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: A vulnerability in libssh allows a remote, authenticated attacker to disclose sensitive information, specifically related to the improper handling of SSH agent forwarding requests.
    confidence_band: high
cves:
  - id: CVE-2023-6004
    cvss: 4.8
    epss: 0.00449
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-1385
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6004
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  mitigation_plan:
    - priority: immediate
      action: Upgrade libssh to 0.10.6 or later on all systems
      owner: IT Operations
      addresses: CVE-2023-6004
      evidence: libssh library vulnerability disclosure
---

The vulnerability, identified as CVE-2023-6004, affects the libssh library. It arises from the improper handling of SSH agent forwarding requests within the implementation. An attacker who has already achieved an authenticated session can exploit this flaw to induce the server to disclose sensitive information that would otherwise be protected by the protocol's expected boundaries. This issue affects versions of libssh prior to 0.10.6. Organizations relying on libssh for remote management or secure communication should prioritize updating to the latest secure version to mitigate the risk of unauthorized information access.

## Impact

Successful exploitation of this vulnerability allows an authenticated attacker to access sensitive information from the memory space or communication channel associated with the affected session. While this requires prior authentication, it poses a risk to environments where multiple users or processes might interact with shared SSH agent instances, potentially leading to unauthorized data exfiltration or access to secondary services protected by those agents.

## Recommendation

Update the libssh library to version 0.10.6 or later across all internal applications and dependent infrastructure. Ensure that all downstream software distributions consuming libssh as a dependency are rebuilt and updated to incorporate the patched version.
