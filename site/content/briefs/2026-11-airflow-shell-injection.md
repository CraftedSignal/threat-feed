---
brief_id: brief-2026-11-09-airflow-shell-injection
event_id: brief-2026-11-09-airflow-shell-injection
revision: 1
activity_at: "2026-11-09T09:13:48Z"
title: 'Apache Airflow: Shell command injection in example_dag_decorator (CVE-2026-101031)'
slug: 2026-11-airflow-shell-injection
description: The `example_dag_decorator` DAG in Apache Airflow versions 3.0.5 through 3.3.x is vulnerable to shell command injection via IPv6 zone identifiers when example DAGs are enabled.
date: "2026-11-09T09:13:48Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: D
  credibility: "3"
  rating: D3
  likelihood: roughly even chance
vendors:
  - Apache
products:
  - Airflow (3.0.5 through 3.3.x)
cves:
  - id: CVE-2026-101031
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/591
---

The `example_dag_decorator` example DAG shipped with Apache Airflow validates an IP address using Python's `ipaddress` module and passes it into a shell command. Because `ipaddress` accepts IPv6 zone identifiers containing arbitrary characters, a user who can trigger the DAG when example DAGs are enabled can facilitate shell command injection.
