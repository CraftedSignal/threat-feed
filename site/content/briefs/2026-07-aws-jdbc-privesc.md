---
title: Privilege Escalation in AWS Advanced JDBC Wrapper for Aurora PostgreSQL
slug: 2026-07-aws-jdbc-privesc
description: A privilege escalation vulnerability (CVE-2026-11400) exists in the AWS Advanced JDBC Wrapper for Amazon Aurora PostgreSQL, affecting versions 3.0.0 through 4.0.0. A low-privileged authenticated user can craft a function to execute with rds_superuser permissions.
date: "2026-07-17T18:41:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - cloud
  - aws
  - postgresql
vendors:
  - Amazon
products:
  - AWS Advanced JDBC Wrapper (versions 3.0.0 through 4.0.0)
  - Amazon Aurora PostgreSQL
cves:
  - id: CVE-2026-11400
    cvss: 8
    epss: 0.00305
references:
  - https://github.com/advisories/GHSA-mhww-p97m-3368
---

A critical privilege escalation vulnerability, tracked as CVE-2026-11400, has been identified in the AWS Advanced JDBC Wrapper when used with Amazon Aurora PostgreSQL instances. This issue affects versions of the wrapper from 3.0.0 up to, but not including, 4.0.1. The vulnerability allows an authenticated user with low privileges to create a specially crafted PostgreSQL function. When executed, this function can exploit the flaw in the JDBC Wrapper to run with the permissions of other Amazon Relational Database Service (RDS) users, specifically escalating to the `rds_superuser` role. This grants the attacker full administrative control over the affected Aurora PostgreSQL database, posing a significant risk to data integrity, confidentiality, and availability. Defenders should prioritize patching and monitoring for unusual database activities, especially related to function creation and execution by low-privileged accounts.

## Attack Chain

1. An authenticated, low-privilege user connects to an affected Amazon Aurora PostgreSQL instance.
2. The user leverages the vulnerability (CVE-2026-11400) in the AWS Advanced JDBC Wrapper.
3. The user creates a specially crafted PostgreSQL function designed to exploit the wrapper's insecure handling of permissions.
4. Upon execution, the crafted function bypasses normal permission checks due to the vulnerability present in the AWS Advanced JDBC Wrapper.
5. The function successfully executes with the elevated permissions of the `rds_superuser` role.
6. The attacker gains full administrative control over the Amazon Aurora PostgreSQL database instance, enabling access to all data and the ability to modify database configurations.

## Impact

Successful exploitation of CVE-2026-11400 leads to complete compromise of the Amazon Aurora PostgreSQL database instance. An attacker can gain `rds_superuser` privileges, allowing them to access, modify, or delete any data within the database. This includes sensitive customer information, critical application data, and database configurations. Such a breach can result in significant data loss, regulatory non-compliance, reputational damage, and disruption of services relying on the compromised database. The vulnerability affects any organization utilizing the AWS Advanced JDBC Wrapper with Amazon Aurora PostgreSQL in the specified vulnerable versions.

## Recommendation

* Upgrade the AWS Advanced JDBC Wrapper to version 4.0.1 or newer to remediate CVE-2026-11400 immediately.
* Apply the recommended workaround by removing the public schema from the search path for your Amazon Aurora PostgreSQL instances.
* Review PostgreSQL database logs for unusual function creation or execution activities, especially from low-privileged users, as these could indicate attempted exploitation of CVE-2026-11400.
