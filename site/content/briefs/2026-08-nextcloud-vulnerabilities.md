---
title: Multiple Vulnerabilities in Nextcloud Products
slug: 2026-08-nextcloud-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-61527 and CVE-2026-61545, affect Nextcloud Server and Mail components, posing risks to data confidentiality and security policy enforcement.
date: "2026-08-06T15:19:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - nextcloud
  - patch-management
vendors:
  - Nextcloud
products:
  - Nextcloud Server 32
  - Nextcloud Server 33
  - Nextcloud Server 34
  - Nextcloud Enterprise
  - Nextcloud Mail
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0973/
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-99gw-ww6p-f2rr
  - https://github.com/nextcloud/security-advisories/security/advisories/GHSA-vq3v-jv6f-6xp2
  - https://www.cve.org/CVERecord?id=CVE-2026-61527
  - https://www.cve.org/CVERecord?id=CVE-2026-61545
---

The French National Cybersecurity Agency (ANSSI) has published an advisory detailing multiple security vulnerabilities impacting various versions of the Nextcloud Server and Nextcloud Mail applications. The flaws, identified by the project maintainers, could lead to a compromise of data confidentiality and allow for the bypass of established security policies. The affected products include Nextcloud Server versions within the 32.x, 33.x, and 34.x branches, as well as the Mail plugin across multiple versions. Administrators are encouraged to review the referenced GitHub security advisories (GHSA-99gw-ww6p-f2rr and GHSA-vq3v-jv6f-6xp2) to identify specific patch requirements, as exploitation of these vulnerabilities could expose sensitive user data stored within the platform.

## Impact

Successful exploitation of these vulnerabilities enables unauthorized access to restricted data and permits the subversion of internal security controls. Given the nature of Nextcloud as a centralized storage and collaboration platform, these flaws present a significant risk to the integrity and confidentiality of enterprise information. Organizations utilizing these affected versions should prioritize patching to prevent potential data exfiltration or unauthorized access to system features.

## Recommendation

- Upgrade Nextcloud Server and Mail instances immediately to the patched versions specified in the vendor's security advisories.
- Review current logs for unexpected access patterns following an audit of user permissions for sensitive files.
- Apply the updates for Server 32.0.12, 33.0.6, or 34.0.1 depending on the current deployment environment.
- Patch Mail plugin versions to at least 3.7.25, 5.5.16, 5.6.20, or 5.7.13.
