---
title: Apache Airflow OpenSearch Provider Credentials Leak via Task Logs (CVE-2026-43826)
slug: 2026-05-airflow-opensearch-creds-leak
description: The OpenSearch logging provider in Apache Airflow Providers OpenSearch versions before 1.9.1 wrote host URLs containing embedded credentials into task logs, potentially exposing them to unauthorized users with task-log read permission (CVE-2026-43826).
date: "2026-05-10T19:46:52Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - credential-leak
  - airflow
  - opensearch
vendors:
  - Apache
products:
  - Airflow Providers OpenSearch (< 1.9.1)
references:
  - https://seclists.org/oss-sec/2026/q2/464
  - CVE-2026-43826
rules:
  - title: Detect Airflow Task Logs Containing OpenSearch Credentials (CVE-2026-43826)
    description: Detects task logs containing OpenSearch host URLs with embedded credentials, indicating a potential exposure of sensitive information (CVE-2026-43826).
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - file_event
      - linux
  - title: Detect OpenSearch Host URL with Embedded Credentials in Process Arguments (CVE-2026-43826)
    description: Detects a process using an OpenSearch host URL with embedded credentials as a command-line argument, configuration file or environment variable (CVE-2026-43826).
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Apache Airflow Providers OpenSearch versions before 1.9.1 are vulnerable to a credentials leak. When configured with a `host` URL that embeds credentials (e.g., `https://user:password@server.example.com:9200`), the OpenSearch logging provider writes the full host URL, including the embedded credentials, into task logs. This vulnerability, identified as CVE-2026-43826, allows any user with task-log read permission to potentially harvest the backend credentials, leading to unauthorized access or data breaches. The issue was reported on May 10, 2026, and defenders should prioritize upgrading to version 1.9.1 or later.

## Attack Chain

1. An administrator configures the Apache Airflow OpenSearch logging provider.
2. The administrator includes credentials directly within the `host` URL of the OpenSearch configuration (e.g., `https://user:password@opensearch.example.com:9200`).
3. Airflow executes a task that generates logs.
4. The OpenSearch logging provider writes the task logs, including the full `host` URL with embedded credentials, to the Airflow task logs.
5. A user with read access to the Airflow task logs views the logs through the Airflow UI or API.
6. The user observes the OpenSearch `host` URL, which contains the plaintext credentials.
7. The attacker uses the harvested credentials to access the OpenSearch cluster.
8. The attacker gains unauthorized access to data stored within the OpenSearch cluster.

## Impact

Successful exploitation of this vulnerability (CVE-2026-43826) allows unauthorized users with task-log read permission to obtain sensitive credentials for the OpenSearch cluster. The impact is significant as it can lead to a complete compromise of the OpenSearch backend, allowing attackers to read, modify, or delete data stored within the cluster. This vulnerability affects all Apache Airflow Providers OpenSearch installations prior to version 1.9.1 that use embedded credentials in the OpenSearch host URL.

## Recommendation

*   Upgrade Apache Airflow Providers OpenSearch to version 1.9.1 or later to remediate CVE-2026-43826.
*   Review and sanitize existing Airflow task logs to remove any instances of embedded credentials.
*   Avoid embedding credentials directly in the OpenSearch `host` URL. Use alternative authentication mechanisms such as environment variables or secrets management.
*   Restrict access to Airflow task logs based on the principle of least privilege.
