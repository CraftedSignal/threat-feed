---
title: Cross-Exchange Data Disclosure in Apache Camel Thrift Component
slug: 2026-10-camel-thrift-data-disclosure
description: A vulnerability in the camel-thrift component, CVE-2026-85245, allows cross-tenant data disclosure by reusing a shared object instance for unmarshalling Thrift payloads.
date: "2026-10-19T12:17:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - data-disclosure
  - apache-camel
  - cve-2026-85245
vendors:
  - Apache
products:
  - camel-thrift (4.0.0-4.18.4, 4.19.0-4.22.0)
cves:
  - id: CVE-2026-85245
    cvss: 5.9
references:
  - https://camel.apache.org/security/CVE-2026-85245.html
  - https://issues.apache.org/jira/browse/CAMEL-24442
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Apache Camel to 4.18.5, 4.22.1, or 4.23.0
      owner: IT Operations
      due: 72h
      evidence: Vendor advisory confirms fix in these versions
  mitigation_plan:
    - priority: medium_term
      action: Implement object copying in code to ensure isolation of unmarshalled bodies
      owner: Development
      addresses: CVE-2026-85245
      evidence: Suggested mitigation in advisory for unpatchable environments
---

Apache Camel’s `camel-thrift` component is vulnerable to a cross-exchange data disclosure flaw identified as CVE-2026-85245. The vulnerability resides in `ThriftDataFormat.unmarshal`, which deserializes incoming data into a shared `defaultInstance` rather than creating a fresh object per exchange. Because this instance is process-wide, fields absent from a subsequent Thrift payload retain values from previous messages. In multi-tenant or shared-route environments, this results in data leakage where one user or tenant may inadvertently read sensitive data belonging to another user. This issue affects Apache Camel versions 4.0.0 through 4.18.4 and 4.19.0 through 4.22.0. The vulnerability is mitigated in versions 4.18.5, 4.22.1, and 4.23.0, where the implementation ensures a deep copy of the `defaultInstance` is created for every exchange.

## Impact

Successful exploitation leads to unauthorized access to sensitive data across different sessions or tenants sharing the same Camel route. This impacts multi-tenant applications using Apache Camel for Thrift-based data processing, potentially exposing PII, credentials, or other private payload content that persists in the shared object instance across concurrent or sequential exchanges.

## Recommendation

1. Upgrade Apache Camel deployments to versions 4.18.5, 4.22.1, or 4.23.0 to incorporate the fix for CVE-2026-85245.
2. If patching is not immediately feasible, modify application code to manually copy the unmarshalled body into a new instance immediately after the data format operation and ensure no references to the returned shared object are retained.
