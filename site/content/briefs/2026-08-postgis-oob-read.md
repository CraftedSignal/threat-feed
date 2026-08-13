---
title: Out-of-Bounds Read Vulnerability in PostGIS FlatGeobuf Decoder
slug: 2026-08-postgis-oob-read
description: PostGIS versions prior to 3.7.0beta2 are vulnerable to an out-of-bounds read in the FlatGeobuf property metadata decoder, allowing authenticated attackers to trigger a denial of service or perform memory disclosure via malformed input.
date: "2026-08-13T16:57:01Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - postgis
  - memory-corruption
products:
  - PostGIS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: PostGIS before 3.7.0beta2 contains an out-of-bounds read vulnerability that allows attackers to cause memory disclosure or a server crash
    confidence_band: high
cves:
  - id: CVE-2026-73515
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73515
  - https://www.vulncheck.com/advisories/postgis-0beta2-out-of-bounds-read-via-flatgeobuf-buffer
  - https://gitea.osgeo.org/postgis/postgis/raw/tag/3.7.0beta2/NEWS
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Database Administrators
  immediate_actions:
    - action: Patch PostGIS extension to version 3.7.0beta2 or higher
      owner: Database Administrators
      due: 48h
      evidence: CVE-2026-73515 fix requirement
  mitigation_plan:
    - priority: immediate
      action: Review and restrict access to PostGIS spatial functions
      owner: Database Administrators
      addresses: CVE-2026-73515
      evidence: Source advisory
---

PostGIS, a widely used spatial database extender for PostgreSQL, contains an out-of-bounds read vulnerability (CVE-2026-73515) in its FlatGeobuf property metadata decoder. The flaw exists because the decoder verifies the presence of a string length field within the provided FlatGeobuf buffer but fails to validate that the associated string body is fully contained within the buffer boundaries before materializing the value into a SQL-visible object. 

This vulnerability can be exploited by an authenticated attacker to perform unauthorized memory disclosure or trigger a server crash, resulting in a denial of service condition. The issue affects all versions of PostGIS prior to 3.7.0beta2. Given that PostGIS is commonly deployed in cloud-managed database environments (such as Neon or Supabase) and exposed via SQL interfaces, this flaw poses a significant risk to data confidentiality and service availability for applications that process untrusted geospatial data.

## Attack Chain

1. Attacker obtains access to a database instance where the PostGIS extension is enabled and accessible via SQL.
2. Attacker crafts a malformed FlatGeobuf buffer containing an inconsistent string length field.
3. Attacker executes a SQL query that invokes a PostGIS function (e.g., ST_GeomFromFlatGeobuf) and passes the malicious buffer as an argument.
4. The PostGIS FlatGeobuf decoder parses the metadata and identifies the string length field.
5. The decoder fails to validate the buffer boundary, resulting in an out-of-bounds memory read when attempting to process the string body.
6. The database engine returns sensitive memory contents as a result of the SQL query (memory disclosure) or triggers an unhandled segmentation fault (crash).
7. Final objective is achieved: exfiltrating private process memory or rendering the database service unresponsive.

## Impact

Successful exploitation of this vulnerability allows authenticated attackers to disclose sensitive information stored in memory or cause a denial of service by crashing the PostgreSQL backend process. This poses a particular risk to multi-tenant or managed database environments where users may be able to influence the data passed to PostGIS functions. The vulnerability has been assigned a CVSS 3.1 score of 8.1 (High).

## Recommendation

Prioritize the following actions to mitigate the risk associated with CVE-2026-73515:

- Upgrade the PostGIS extension to version 3.7.0beta2 or later immediately.
- Audit database access logs to identify users or service accounts that frequently invoke PostGIS functions, specifically those handling FlatGeobuf input.
- Review and restrict database permissions to ensure that only trusted users have the ability to execute spatial functions involving external data types.
- Monitor database error logs for repeated segmentation faults or process crashes, which may indicate attempted exploitation of this memory corruption vulnerability.
