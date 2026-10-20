---
brief_id: brief-2026-10-apache-camel-mllp-phi-exposure
event_id: brief-2026-10-apache-camel-mllp-phi-exposure
revision: 1
activity_at: "2026-10-20T10:32:40Z"
title: 'Apache Camel: Information disclosure of PHI via MLLP log files (CVE-2026-85260)'
slug: 2026-10-apache-camel-mllp-phi-exposure
description: CVE-2026-85260 is an information disclosure vulnerability in the Apache Camel MLLP component where sensitive HL7 clinical messages are written to application logs by default, exposing protected health information.
date: "2026-10-20T10:32:40Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against Apache Security Advisory
cpes:
  - cpe:2.3:a:apache:camel:*:*:*:*:*:*:*:*
tags:
  - apache
  - information-disclosure
  - camel
  - hl7
  - phi
  - cve-2026-85260
vendors:
  - Apache
products:
  - camel-mllp (4.0.0 - 4.18.4, 4.19.0 - 4.22.0)
  - Camel Spring Boot (4.22.0)
  - Camel Quarkus (4.15.0)
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Information Repository
    evidence: The MLLP component writes HL7 payload content to application logs, exposing sensitive health information.
    confidence_band: high
cves:
  - id: CVE-2026-85260
    cvss: 5.5
    kev_status: unknown
references:
  - https://camel.apache.org/security/CVE-2026-85260.html
  - https://issues.apache.org/jira/browse/CAMEL-24454
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Compliance
  immediate_actions:
    - action: Upgrade Apache Camel to versions 4.18.5, 4.22.1, or 4.23.0.
      owner: IT Operations
      due: 72h
      evidence: Apache security advisory
  mitigation_plan:
    - priority: immediate
      action: Set logPhi=false and restrict log file access permissions
      owner: IT Operations
      addresses: CVE-2026-85260
      evidence: Source advisory mitigation section
---

Apache Camel contains an information disclosure vulnerability (CVE-2026-85260) within the `camel-mllp` component. The `logPhi` configuration option, which controls whether HL7 payload data is written to application logs, defaulted to `true` in versions prior to the patch. This resulted in clinical PHI (Protected Health Information) being written to log files in plain text out of the box. Additionally, two internal code paths in the `camel-mllp` component were found to log payload content regardless of the `logPhi` setting. This exposure allows unauthorized entities with access to log aggregation, storage, or monitoring systems to view sensitive medical data. The issue affects Camel versions 4.0.0 through 4.18.4, and 4.19.0 through 4.22.0. The vulnerability is mitigated by upgrading to version 4.18.5, 4.22.1, or 4.23.0, which changes the default `logPhi` value to `false` and suppresses PHI logging in previously ignored code paths.

## Impact

Successful exploitation or accidental exposure leads to the storage of plain-text PHI in log management systems (e.g., ELK, Splunk). If these logs are not strictly protected, this constitutes a violation of HIPAA or similar healthcare data privacy regulations. The number of potentially impacted systems includes any healthcare integration environment utilizing the `camel-mllp` component for HL7 message processing.

## Recommendation

* Upgrade Apache Camel dependencies to version 4.18.5, 4.22.1, or 4.23.0 to ensure the `logPhi` option defaults to `false` and PHI is suppressed.
* If immediate patching is not feasible, explicitly set `logPhi=false` in the MLLP component configuration; note that this does not remediate the two identified code paths that continue to log data until the patch is applied.
* Review existing log management policies and access controls for all environments running `camel-mllp` to identify and restrict unauthorized access to application log files containing potential HL7/PHI data.
* Implement log scrubbing or redaction patterns in log aggregation pipelines (e.g., Logstash filters or SIEM ingest pipelines) to identify and mask HL7 PID segments or other sensitive markers if logs cannot be immediately cleared.
