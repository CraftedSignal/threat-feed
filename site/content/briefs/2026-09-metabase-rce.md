---
title: Authenticated Remote Code Execution in Metabase via H2 Deserialization
slug: 2026-09-metabase-rce
description: Metabase instances configured with H2 databases are vulnerable to authenticated remote code execution via insecure Java deserialization triggered through native SQL queries, identified as CVE-2026-59827.
date: "2026-09-03T13:53:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:metabase:metabase:*:*:*:*:*:*:*:*
  - cpe:2.3:a:metabase:metabase:*:*:*:*:-:*:*:*
  - cpe:2.3:a:metabase:metabase:*:*:*:*:enterprise:*:*:*
vendors:
  - Metabase
products:
  - Metabase (0.58.0 - 0.58.14, 0.59.0 - 0.59.11, 0.60.0 - 0.60.6.2, 0.61.0 - 0.61.1.3)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An authenticated user with permission to execute native queries against an accessible H2 database can exploit this behavior to execute arbitrary operating-system commands on the Metabase server.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Metabase instances with an H2 database connection, including the default sample database, deserialize arbitrary Java objects returned by native H2 queries in result columns of type OTHER without validation.
    confidence_band: high
cves:
  - id: CVE-2026-59827
    cvss: 9.9
    epss: 0.00934
references:
  - https://www.exploit-db.com/exploits/52680
  - https://github.com/metabase/metabase/security/advisories/GHSA-w95f-x9v9-wv36
rules:
  - title: Detect CVE-2026-59827 Exploitation Attempt
    description: Detects exploitation attempts against Metabase by monitoring native SQL queries containing the CAST function and potential hex-encoded serialized Java objects directed at H2 databases.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Metabase to 1.58.15 or later
      owner: IT Operations
      due: 24h
      evidence: Vendor advisory GHSA-w95f-x9v9-wv36
  hunt_leads:
    - lead: Search logs for POST /api/dataset requests containing 'CAST(X' and 'AS OTHER' tokens
      technique_id: T1203
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Publicly available exploit code utilizes this pattern
  mitigation_plan:
    - priority: immediate
      action: Disable the sample H2 database and restrict native query access
      owner: IT Operations
      addresses: CVE-2026-59827
      evidence: Vulnerability analysis indicates requirements include access to H2 and native query permissions
---

Metabase versions 0.58.0 through 0.61.1.4 are affected by a high-severity vulnerability (CVE-2026-59827) that allows authenticated attackers to achieve remote code execution (RCE). The vulnerability stems from insecure deserialization of Java objects within the H2 database engine, which Metabase uses for its internal data storage, including the default sample database. 

When an attacker with sufficient privileges to execute native SQL queries interacts with an H2 database instance, they can leverage the 'OTHER' data type to pass arbitrary serialized Java objects to the application. Because the application fails to validate these objects, they are deserialized upon retrieval, leading to arbitrary code execution with the permissions of the Metabase process. This vulnerability is particularly dangerous for instances where the sample H2 database remains active and accessible to authenticated users. Defenders should prioritize patching to the versions listed in the vendor advisory.

## Attack Chain

1. The attacker authenticates to the target Metabase instance with valid user credentials.
2. The attacker navigates to the query interface and identifies an accessible H2 database connection.
3. The attacker crafts a malicious serialized Java object payload using external tooling.
4. The attacker executes a native SQL query via the Metabase '/api/dataset' endpoint containing the payload cast to the H2 'OTHER' data type.
5. The Metabase application processes the query and retrieves the data from the H2 database.
6. The application performs insecure deserialization of the object returned in the query result column.
7. The Java deserialization process triggers the execution of arbitrary system commands on the underlying server host.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary OS commands on the host running the Metabase application. This can lead to complete server compromise, including data exfiltration, lateral movement within the environment, and persistence establishment. The vulnerability affects a broad range of recent Metabase versions across various deployment environments.

## Recommendation

Prioritize patching all Metabase installations to versions that address CVE-2026-59827 as documented in the GitHub security advisory GHSA-w95f-x9v9-wv36. If immediate patching is not possible, disable the sample H2 database and restrict 'native query' permissions for all non-administrative users.

## Detection Engineering

Deploy monitoring for the following patterns in web server access logs to identify exploitation attempts:

1. Enable web server logging for the '/api/dataset' endpoint to capture POST requests containing SQL queries.
2. Monitor for native SQL queries involving the CAST function directed at H2-type databases that include suspicious hex strings or references to deserialization gadgets.
3. Audit for unauthorized access to the '/api/dataset' endpoint by users without explicit database query permissions.
