---
title: Multiple Vulnerabilities in PostgreSQL
slug: 2026-08-postgresql-vulns
description: PostgreSQL has released patches for multiple high-severity vulnerabilities across several versions that could allow remote attackers to achieve arbitrary code execution, perform SQL injection, or conduct denial-of-service attacks.
date: "2026-08-14T14:05:46Z"
lastmod: "2026-08-18T13:58:06Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=0EC9A618-6649-5865-974D-61A43F5636D2&utm_source=rss&utm_medium=rss
tags:
  - vulnerability
  - database
  - security-patch
vendors:
  - PostgreSQL
products:
  - PostgreSQL 14
  - PostgreSQL 15
  - PostgreSQL 16
  - PostgreSQL 17
  - PostgreSQL 18
  - PostgreSQL
cves:
  - id: CVE-2026-14671
    cvss: 8.8
    epss: 0.00405
  - id: CVE-2026-14662
    cvss: 8.8
    epss: 0.00655
  - id: CVE-2026-14672
    cvss: 5.3
    epss: 0.00394
  - id: CVE-2026-15742
    cvss: 8.8
    epss: 0.00479
  - id: CVE-2026-16239
    cvss: 8.8
    epss: 0.0059
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1024/
  - https://www.postgresql.org/about/news/postgresql-186-1711-1615-1519-1424-and-19-beta-3-released-3365/
  - https://www.cve.org/CVERecord?id=CVE-2026-14662
  - https://www.cve.org/CVERecord?id=CVE-2026-14663
  - https://www.cve.org/CVERecord?id=CVE-2026-14664
  - https://www.cve.org/CVERecord?id=CVE-2026-14666
  - https://www.cve.org/CVERecord?id=CVE-2026-14668
  - https://www.cve.org/CVERecord?id=CVE-2026-14669
  - https://www.cve.org/CVERecord?id=CVE-2026-14670
  - https://www.cve.org/CVERecord?id=CVE-2026-14671
  - https://www.cve.org/CVERecord?id=CVE-2026-14672
  - https://www.cve.org/CVERecord?id=CVE-2026-14673
  - https://www.cve.org/CVERecord?id=CVE-2026-14676
  - https://www.cve.org/CVERecord?id=CVE-2026-14677
  - https://www.cve.org/CVERecord?id=CVE-2026-14678
  - https://www.cve.org/CVERecord?id=CVE-2026-14679
  - https://www.cve.org/CVERecord?id=CVE-2026-14680
  - https://www.cve.org/CVERecord?id=CVE-2026-14681
  - https://www.cve.org/CVERecord?id=CVE-2026-15741
  - https://www.cve.org/CVERecord?id=CVE-2026-15742
  - https://www.cve.org/CVERecord?id=CVE-2026-16238
  - https://www.cve.org/CVERecord?id=CVE-2026-16239
  - https://www.cve.org/CVERecord?id=CVE-2026-16241
  - https://www.cve.org/CVERecord?id=CVE-2026-18024
  - https://www.cve.org/CVERecord?id=CVE-2026-18408
  - https://www.cve.org/CVERecord?id=CVE-2026-19385
  - https://www.cve.org/CVERecord?id=CVE-2026-6464
  - https://www.cve.org/CVERecord?id=CVE-2026-6469
  - https://www.cve.org/CVERecord?id=CVE-2026-6470
  - https://www.cve.org/CVERecord?id=CVE-2026-6471
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2844
  - https://sploitus.com/exploit?id=0EC9A618-6649-5865-974D-61A43F5636D2&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all PostgreSQL instances to current safe versions
      owner: IT Operations
      due: 48h
      evidence: Vendor release bulletin advises upgrading to address identified CVEs
  mitigation_plan:
    - priority: immediate
      action: Upgrade PostgreSQL versions
      owner: IT Operations
      addresses: All CVEs listed in brief
      evidence: Vendor security bulletin
updates:
  - at: "2026-08-14T14:06:27Z"
    level: L2
    summary: added CVE-2026-14678 +3
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2844
  - at: "2026-08-18T13:58:06Z"
    level: L2
    summary: poc_available; added CVE-2026-14662 +3
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=0EC9A618-6649-5865-974D-61A43F5636D2&utm_source=rss&utm_medium=rss
---

On August 13, 2026, the PostgreSQL Global Development Group released updates addressing a significant number of vulnerabilities affecting multiple versions of the database management system. These vulnerabilities, tracked under various CVE identifiers, range in impact from SQL injection and data confidentiality breaches to remote code execution (RCE) and denial-of-service (DoS) conditions. The affected software branches include versions 14, 15, 16, 17, and 18. Given the critical nature of database infrastructure and the potential for unauthorized code execution or data exfiltration, administrators are urged to verify their current PostgreSQL version and apply the vendor-provided patches immediately. This update cycle serves as a critical maintenance release to remediate security flaws discovered during routine auditing and vulnerability assessment processes.

## Impact

Successful exploitation of these vulnerabilities could lead to total database compromise, including the exfiltration of sensitive information, the execution of arbitrary commands with the privileges of the database service, or the disruption of critical business operations through service instability. Organizations failing to patch these systems remain vulnerable to unauthenticated or authenticated attackers depending on the specific CVE being leveraged, potentially leading to unauthorized system access or loss of data integrity.

## Recommendation

* Immediately inventory all PostgreSQL database instances and identify versions falling within the vulnerable ranges (prior to 14.24, 15.19, 16.15, 17.11, and 18.6).
* Upgrade all identified instances to the latest patched releases provided by the PostgreSQL project.
* Review database access logs for unusual queries or unauthorized connection attempts, particularly those targeting system-level configuration or internal function calls, as these may indicate attempted exploitation of SQL injection or RCE flaws.
* Ensure database services are running with the principle of least privilege, minimizing the potential impact should an attacker gain code execution.
