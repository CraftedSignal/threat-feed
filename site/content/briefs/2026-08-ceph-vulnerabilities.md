---
title: Multiple Security Vulnerabilities in Ceph Storage Cluster
slug: 2026-08-ceph-vulnerabilities
description: Multiple vulnerabilities in Ceph versions 19.2.6 and 20.2.4 and earlier expose clusters to privilege escalation, data confidentiality compromise, and security policy bypass.
date: "2026-08-20T19:12:00Z"
type: advisory
types:
  - advisory
severities:
  - high
products:
  - Ceph (20.2.x)
  - Ceph (19.2.x)
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1057/
  - https://github.com/ceph/ceph/security/advisories/GHSA-7q3q-3975-qw3q
  - https://github.com/ceph/ceph/security/advisories/GHSA-j73r-qrgx-jvq2
  - https://github.com/ceph/ceph/security/advisories/GHSA-rg9p-5xcp-wm8h
  - https://github.com/ceph/ceph/security/advisories/GHSA-rmjq-ffrm-j6vj
  - https://www.cve.org/CVERecord?id=CVE-2025-30156
  - https://www.cve.org/CVERecord?id=CVE-2026-39944
  - https://www.cve.org/CVERecord?id=CVE-2026-50152
  - https://www.cve.org/CVERecord?id=CVE-2026-54330
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Ceph clusters to version 20.2.4 or 19.2.6 or later.
      owner: IT Operations
      due: 48h
      evidence: Source advises upgrading to resolve vulnerabilities.
---

The French National Cybersecurity Agency (ANSSI) has published a security advisory detailing multiple vulnerabilities affecting the Ceph storage platform. These vulnerabilities, identified through several GitHub security advisories (GHSA-7q3q-3975-qw3q, GHSA-j73r-qrgx-jvq2, GHSA-rg9p-5xcp-wm8h, and GHSA-rmjq-ffrm-j6vj), impact Ceph versions 20.2.x prior to 20.2.4 and versions prior to 19.2.6.

The vulnerabilities collectively allow attackers to achieve privilege escalation, access sensitive data, or bypass existing security policies within the storage infrastructure. Given that Ceph is widely used for scalable storage in enterprise and cloud environments, successful exploitation could lead to unauthorized access to large volumes of data or disruption of storage management services. Defenders are advised to audit their current Ceph deployments and upgrade to the patched versions as recommended by the upstream project.

## Impact

Successful exploitation of these vulnerabilities may result in full unauthorized access to sensitive data stored within Ceph clusters, the ability for lower-privileged users to escalate their permissions to administrative levels, and the subversion of internal security policies. Organizations operating Ceph clusters for high-availability storage, cloud orchestration, or big data processing are particularly at risk of data breach or loss of integrity.

## Recommendation

- Identify all instances of Ceph within the environment and verify version numbers against the affected ranges (versions < 19.2.6 and < 20.2.4 for 20.2.x).
- Apply the vendor-provided patches by upgrading to the latest stable versions of Ceph.
- Review access logs and audit trails for unauthorized administrative actions or unexpected data access patterns during the period following the release of these advisories.
- Review the specific GHSA references provided in the source documentation to understand the exploit surface of each CVE (CVE-2025-30156, CVE-2026-39944, CVE-2026-50152, and CVE-2026-54330).
