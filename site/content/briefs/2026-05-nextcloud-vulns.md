---
title: Multiple Vulnerabilities in Nextcloud Products
slug: 2026-05-nextcloud-vulns
description: Multiple vulnerabilities in Nextcloud products can lead to data confidentiality breaches, data integrity compromise, and security policy bypass.
date: "2026-05-12T14:12:08Z"
lastmod: "2026-07-11T09:00:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:nextcloud:nextcloud_server:*:*:*:*:-:*:*:*
  - cpe:2.3:a:nextcloud:nextcloud_server:*:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:nextcloud:calendar:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=C9D8D26E-43CB-5CB0-AF87-263E8FED095F&utm_source=rss&utm_medium=rss
tags:
  - nextcloud
  - vulnerability
  - security-policy-bypass
vendors:
  - Nextcloud
  - Coollabs
products:
  - Android Files
  - Calendar
  - Collectives app
  - End-to-End Encryption
  - Nextcloud Enterprise Server
  - Nextcloud Server
  - User OIDC
  - Coolify < v4.0.0-beta.469
affected_os:
  - Linux
cves:
  - id: CVE-2026-45153
    cvss: 4.6
    epss: 0.00153
  - id: CVE-2026-45154
    cvss: 2.6
    epss: 0.00189
  - id: CVE-2026-45157
    cvss: 6.3
    epss: 0.00231
  - id: CVE-2026-45282
    cvss: 6.5
    epss: 0.00294
  - id: CVE-2026-45286
    cvss: 4.3
    epss: 0.00281
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0569/
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-2w7v-5299-3hw5
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-35fx-69q6-xpjr
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-45pj-p7x7-4mhc
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-79xf-ffj8-96fm
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-8mpv-ggq8-hf3w
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-p3qw-7gwx-wg24
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-qqgv-fqwp-mjpp
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-r3xh-x86g-hw4m
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-r697-74m9-gvf2
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-xpgv-grf9-gm7x
  - https://www.cve.org/CVERecord?id=CVE-2026-45153
  - https://www.cve.org/CVERecord?id=CVE-2026-45154
  - https://www.cve.org/CVERecord?id=CVE-2026-45155
  - https://www.cve.org/CVERecord?id=CVE-2026-45156
  - https://www.cve.org/CVERecord?id=CVE-2026-45157
  - https://www.cve.org/CVERecord?id=CVE-2026-45159
  - https://www.cve.org/CVERecord?id=CVE-2026-45282
  - https://www.cve.org/CVERecord?id=CVE-2026-45284
  - https://www.cve.org/CVERecord?id=CVE-2026-45285
  - https://www.cve.org/CVERecord?id=CVE-2026-45286
  - https://sploitus.com/exploit?id=C9D8D26E-43CB-5CB0-AF87-263E8FED095F&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=C9D8D26E-43CB-5CB0-AF87-263E8FED095F
  - type: url
    value: https://github.com/coollabsio/coolify/security/advisories/GHSA-4fhp-xqqp-w7vv
  - type: url
    value: https://github.com/cybertechajju/CVE-2026-59734.git
  - type: domain
    value: coolify.io
  - type: url
    value: https://medium.com/@cybertechajju/how-i-found-an-os-command-injection-rce-in-coolify-a93ffce24e74
  - type: url
    value: https://youtube.com/@cybertechajju
ioc_counts:
  domain: 1
  url: 5
rules:
  - title: Detect CVE-2026-45282 Exploitation Attempt - Suspicious Nextcloud URI Access
    description: Detects CVE-2026-45282 exploitation attempt - Access to specific Nextcloud URIs potentially indicating an attack.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-45284 Exploitation Attempt - Suspicious File Upload
    description: Detects CVE-2026-45284 exploitation attempt - HTTP POST requests to upload endpoints with suspicious file extensions.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-07-11T09:00:54Z"
    level: L2
    summary: poc_available; added CVE-2026-45153 +4; OS linux
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=C9D8D26E-43CB-5CB0-AF87-263E8FED095F&utm_source=rss&utm_medium=rss
---

On May 12, 2026, CERT-FR published an advisory regarding multiple vulnerabilities affecting various Nextcloud products. These vulnerabilities can potentially allow an attacker to compromise the confidentiality and integrity of data, as well as bypass security policies. The affected products include Nextcloud Enterprise Server, Nextcloud Server, Android Files, Calendar, Collectives app, End-to-End Encryption, and User OIDC, spanning multiple versions. Organizations using Nextcloud should review the specific versions listed in the advisory and apply the necessary updates to mitigate these risks. The specific nature of the vulnerabilities is not detailed beyond the impact, requiring administrators to consult the linked security advisories from Nextcloud to understand the specific attack vectors.

## Attack Chain

Since the specific nature of the vulnerabilities are not detailed, the following attack chain is generalized based on common web application vulnerabilities:

1.  An attacker identifies a vulnerable Nextcloud instance.
2.  The attacker crafts a malicious request targeting one of the identified vulnerabilities (CVE-2026-45153, CVE-2026-45154, CVE-2026-45155, CVE-2026-45156, CVE-2026-45157, CVE-2026-45159, CVE-2026-45282, CVE-2026-45284, CVE-2026-45285, CVE-2026-45286).
3.  The attacker sends the crafted request to the vulnerable Nextcloud endpoint.
4.  The vulnerable Nextcloud component processes the malicious request.
5.  Depending on the vulnerability, the attacker may be able to read sensitive data (data confidentiality breach), modify data (data integrity compromise), or bypass security checks (security policy bypass).
6.  The attacker escalates privileges within the Nextcloud instance.
7.  The attacker moves laterally to other systems accessible from the compromised Nextcloud instance.

## Impact

Successful exploitation of these vulnerabilities could lead to unauthorized access to sensitive data stored within Nextcloud, modification of data, and the circumvention of security policies. This could result in significant financial loss, reputational damage, and legal repercussions. The advisory does not specify the number of affected organizations, but given Nextcloud's widespread use, the potential impact could be substantial.

## Recommendation

*   Apply the security patches provided by Nextcloud for the affected products and versions listed in the advisory, specifically Nextcloud Enterprise Server, Nextcloud Server, Android Files, Calendar, Collectives app, End-to-End Encryption, and User OIDC.
*   Monitor web server logs for suspicious activity targeting Nextcloud endpoints, specifically looking for unusual HTTP requests or error codes (related to the listed CVEs).
*   Deploy the provided Sigma rules to detect potential exploitation attempts against Nextcloud instances.
*   Review and harden Nextcloud security configurations based on Nextcloud's official security recommendations.
