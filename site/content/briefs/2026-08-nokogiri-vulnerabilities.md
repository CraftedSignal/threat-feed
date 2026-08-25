---
title: Vulnerabilities in Nokogiri Vendored libxml2 and libxslt Libraries
slug: 2026-08-nokogiri-vulnerabilities
description: Nokogiri versions prior to 1.13.2 bundle vulnerable libxml2 2.9.12 and libxslt 1.1.34 libraries, exposing applications to denial of service, memory disclosure, and potential code execution.
date: "2026-08-25T18:09:35Z"
lastmod: "2026-08-25T18:10:00Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
  - cpe:2.3:a:xmlsoft:libxslt:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:a:splunk:universal_forwarder:*:*:*:*:*:*:*:*
  - cpe:2.3:a:splunk:universal_forwarder:9.1.0:*:*:*:*:*:*:*
  - cpe:2.3:a:xmlsoft:libxml2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:ipados:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:iphone_os:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2020-001:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2021-001:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2021-002:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2021-003:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2021-004:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2021-005:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2021-006:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2021-007:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2021-008:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2022-001:*:*:*:*:*:*
  - cpe:2.3:o:apple:mac_os_x:10.15.7:security_update_2022-003:*:*:*:*:*:*
  - cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:tvos:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
  - libxslt
  - nokogiri
vendors:
  - Nokogiri
products:
  - Nokogiri
  - Nokogiri (< 1.18.4)
  - libxslt (< 1.1.43)
cves:
  - id: CVE-2021-30560
    cvss: 8.8
    epss: 0.21458
  - id: CVE-2022-23308
    cvss: 7.5
    epss: 0.0601
  - id: CVE-2022-51000
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-51000
  - https://nvd.nist.gov/vuln/detail/CVE-2021-30560
  - https://nvd.nist.gov/vuln/detail/CVE-2022-23308
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71406
  - https://github.com/sparklemotion/nokogiri/security/advisories/GHSA-mrxw-mxhj-p664
  - https://www.vulncheck.com/advisories/nokogiri-before-use-after-free-via-libxslt
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - AppSec
  immediate_actions:
    - action: Audit Ruby environments for Nokogiri versions < 1.13.2
      owner: AppSec
      due: 72h
      evidence: Source confirms Nokogiri < 1.13.2 contains vulnerable vendored libraries
  mitigation_plan:
    - priority: immediate
      action: Upgrade Nokogiri gem to 1.13.2 or later across all projects
      owner: IT Operations
      addresses: CVE-2022-51000
      evidence: Source states Nokogiri 1.13.2 upgrades vendored libxml2 to 2.9.13 and libxslt to 1.1.35
updates:
  - at: "2026-08-25T18:10:00Z"
    level: L2
    summary: added coverage for Nokogiri (< 1.18.4) +1 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2025-71406
---

Nokogiri versions prior to 1.13.2 (CRuby with packaged libraries) bundle vulnerable versions of libxml2 (2.9.12) and libxslt (1.1.34). These bundled libraries introduce critical security risks to Ruby applications relying on Nokogiri for XML/XSL processing. CVE-2021-30560 in libxslt enables denial-of-service attacks when processing untrusted XSL stylesheets. More severely, CVE-2022-23308 in libxml2 allows for denial-of-service, memory disclosure, or arbitrary code execution if an application parses untrusted XML documents with the DTDVALID option set to true and NOENT set to false. Because these libraries are vendored directly within the Nokogiri gem, simply updating system-level libraries is insufficient; the gem itself must be updated to version 1.13.2 or later to include the patched libxml2 (2.9.13) and libxslt (1.1.35) binaries.

## Impact

Applications using affected versions of Nokogiri are vulnerable to exploitation when processing untrusted input. Successful exploitation can lead to complete service instability (DoS), leakage of sensitive process memory, or full remote code execution, depending on the specific application implementation and the XML parsing flags enabled. This affects any environment utilizing the Ruby gem on any operating system where the packaged libraries are utilized.

## Recommendation

- Identify all Ruby projects utilizing Nokogiri < 1.13.2 by auditing Gemfile.lock files or scanning vendor directory assets.
- Update Nokogiri to version 1.13.2 or later to ensure the inclusion of patched libxml2 2.9.13 and libxslt 1.1.35.
- Review application logic to ensure XML parsing configurations avoid insecure settings like DTDVALID=true when processing untrusted content.
