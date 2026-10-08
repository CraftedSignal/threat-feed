---
title: MariaDB Connector/Node.js Information Disclosure via Uninitialized Heap Memory
slug: 2026-10-mariadb-node-memory-leak
description: An information disclosure vulnerability in the MariaDB Connector/Node.js allows attackers to leak uninitialized heap memory into database entries by providing malformed GeoJSON parameters to execute or batch operations.
date: "2026-10-08T19:43:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*
vendors:
  - MariaDB
products:
  - mariadb (< 3.2.5, >= 3.3.0 < 3.3.4, >= 3.4.0 < 3.4.7, >= 3.5.0-rc.0 < 3.5.4)
cves:
  - id: CVE-2026-107383
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-48qf-xh34-q73r
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107383
action_plan:
  priority: elevated
  owners:
    - Application Security
    - Development Team
  immediate_actions:
    - action: Upgrade mariadb to 3.2.5 or later
      owner: Development Team
      due: 72h
      evidence: Source provides fixed versions for each affected branch.
  mitigation_plan:
    - priority: immediate
      action: Validate GeoJSON structure before passing to connector methods.
      owner: Development Team
      addresses: CVE-2026-107383
      evidence: Source recommends validation as a temporary workaround.
---

The MariaDB Connector/Node.js is vulnerable to an information disclosure issue (CVE-2026-107383) when encoding GeoJSON Polygon or MultiPolygon parameters. The connector incorrectly calculates the required buffer size for these objects using the 'length' property of provided rings. If an attacker provides a non-array object containing a 'length' property (e.g., {"type": "Polygon", "coordinates": {"length": 4000}}), the connector reserves space in a buffer allocated via Buffer.allocUnsafe() but fails to write the intended geometry data into that space.

Because the connector returns the entire buffer regardless of the write progress, the uninitialized heap memory remains in the returned buffer and is subsequently written to the database. This memory can contain sensitive data from the Node.js process, including other users' request/response bodies, session tokens, cookies, database credentials, and TLS key material. The issue affects all versions prior to 3.2.5, 3.3.4, 3.4.7, and 3.5.4. The text-based query() method is not affected.

## Impact

Successful exploitation results in the silent exfiltration of sensitive process heap data directly into the database. Because the leaked data is persisted in rows, backups, and replicas, it remains accessible to any entity with read permissions for the affected tables. This vulnerability poses a high risk to applications handling map or location data where attacker-supplied GeoJSON objects are processed by the connector.

## Recommendation

- Upgrade to MariaDB Connector/Node.js version 3.2.5, 3.3.4, 3.4.7, 3.5.4, or later to implement proper validation of GeoJSON ring types.
- Implement application-level input validation to ensure that all GeoJSON coordinate properties are correctly structured arrays before passing them to execute() or batch() methods.
- Transition from execute() or batch() to the query() method for operations involving GeoJSON parameters if immediate patching is not feasible, as the text-based encoder is not impacted by this heap disclosure.
- Audit database tables containing data populated by vulnerable versions of the connector to identify potentially leaked sensitive information.
