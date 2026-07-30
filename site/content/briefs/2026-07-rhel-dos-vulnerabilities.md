---
title: Denial of Service Vulnerabilities in RHEL perl-Archive-Tar and httplib2
slug: 2026-07-rhel-dos-vulnerabilities
description: Multiple vulnerabilities in Red Hat Enterprise Linux packages perl-Archive-Tar and httplib2 can be exploited by a remote, anonymous attacker to cause a Denial of Service condition.
date: "2026-07-30T13:34:59Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:ruby-lang:rexml:*:*:*:*:*:ruby:*:*
  - cpe:2.3:o:netapp:bootstrap_os:-:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - linux
vendors:
  - Red Hat
products:
  - Enterprise Linux
  - perl-Archive-Tar
  - httplib2
affected_os:
  - RHEL
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An remote, anonymous attacker can exploit multiple vulnerabilities in Red Hat Enterprise Linux to perform a Denial of Service attack.
    confidence_band: high
cves:
  - id: CVE-2024-39908
    cvss: 4.3
    epss: 0.01493
  - id: CVE-2024-39909
    cvss: 6.5
    epss: 0.00443
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2588
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-39908
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-39909
---

Red Hat has issued a security advisory regarding vulnerabilities affecting specific packages within the Red Hat Enterprise Linux (RHEL) ecosystem. The vulnerabilities involve perl-Archive-Tar and httplib2, which can be leveraged by a remote, anonymous attacker to induce a Denial of Service (DoS) condition on affected systems. The issue arises due to flaws within these specific libraries that allow for resource exhaustion or process crashes when handling malformed input. Organizations utilizing RHEL systems that rely on these packages for data processing or network communication are at risk of service interruption. Security teams should prioritize patching or updating the affected packages to the versions provided by Red Hat to remediate CVE-2024-39908 and CVE-2024-39909.

## Impact

The successful exploitation of these vulnerabilities results in a Denial of Service, which can disrupt critical services or applications relying on the vulnerable RHEL packages. While these vulnerabilities are limited to DoS impact, they can be utilized by unauthorized remote actors to degrade system availability in targeted environments.

## Recommendation

Prioritize the identification of RHEL systems running the vulnerable versions of perl-Archive-Tar and httplib2. Apply the security updates provided via the Red Hat errata channels immediately to patch CVE-2024-39908 and CVE-2024-39909. Validate that automated patch management processes are configured to pull the latest updates for RHEL enterprise repositories to ensure coverage for these CVEs.
