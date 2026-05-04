---
title: Apko Package Substitution Vulnerability
slug: 2024-01-apko-package-substitution
description: Apko versions prior to 1.2.7 are vulnerable to package substitution due to not verifying downloaded apk packages against the APKINDEX checksum, potentially allowing an attacker who can substitute download responses to install arbitrary packages into built images.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - package-substitution
  - supply-chain
  - linux
vendors:
  - Chainguard
products:
  - apko
  - go/chainguard.dev/apko
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://github.com/advisories/GHSA-hcwr-pq9g-rq3m
rules:
  - title: Detect Package Installation from Unusual Source After Apko Build
    description: Detects package installation activity from unexpected sources shortly after an apko build process is completed, which could indicate a package substitution attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1195
    data_sources:
      - process_creation
      - linux
  - title: Detect Direct Package Download After Apko Build
    description: Detects direct download of apk packages from unusual sources using wget or curl after an apko build process is completed, which could indicate package substitution or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1195
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Apko, a tool for building container images, is susceptible to a critical package substitution vulnerability in versions prior to 1.2.7. The vulnerability stems from the tool's failure to validate downloaded `.apk` packages against the checksums recorded in the signed `APKINDEX.tar.gz` file. While Apko does verify the signature on the index and parses the checksums, it does not compare these checksums against the downloaded packages during the `getPackageImpl()` function. This oversight can allow an attacker with the ability to manipulate download responses, such as through compromised mirrors, HTTP repositories, or poisoned CDN caches, to inject malicious or unintended packages into the built container images. This issue was reported by Oleh Konko from 1seal.

## Attack Chain

1.  Attacker compromises a mirror, HTTP repository, or poisons a CDN cache used by apko.
2.  A user initiates an apko build process, specifying a package to be included in the image.
3.  Apko requests the specified package from the compromised source.
4.  The attacker substitutes the legitimate package with a malicious or altered `.apk` package.
5.  Apko downloads the substituted package.
6.  Apko verifies the signature on `APKINDEX.tar.gz` but fails to validate the downloaded `.apk` package against the checksum in the index.
7.  Apko installs the malicious or altered package into the container image.
8.  The resulting container image is built with the compromised package, potentially leading to arbitrary code execution or other malicious activity when the image is deployed.

## Impact

Successful exploitation of this vulnerability allows an attacker to inject arbitrary packages into container images built with vulnerable versions of apko. This can lead to a variety of adverse outcomes, including arbitrary code execution within containers, data exfiltration, and denial-of-service attacks. The lack of package validation provides a significant opportunity for attackers to compromise the integrity of containerized applications and infrastructure.

## Recommendation

*   Upgrade to apko version 1.2.7 or later once a fix is available from the vendor.
*   Monitor network traffic for unexpected connections to untrusted or unusual package repositories using network connection logs and create rules to alert on such activity.
*   Implement integrity monitoring on the build system to detect unauthorized modification of files, specifically focusing on downloaded packages. This can be achieved through file integrity monitoring tools that generate file_event logs.
*   Deploy the provided Sigma rule to detect suspicious process executions within containers shortly after the build process.
