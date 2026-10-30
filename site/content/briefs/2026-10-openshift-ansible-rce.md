---
brief_id: brief-2026-10-30-openshift-ansible-rce
event_id: brief-2026-10-30-openshift-ansible-rce
revision: 1
activity_at: "2026-10-30T01:09:54Z"
title: 'Red Hat openshift-ansible: Arbitrary code execution via unverified remote scripts (CVE-2026-92092)'
slug: 2026-10-openshift-ansible-rce
description: The openshift-ansible installer container fetches and executes remote scripts without integrity verification, allowing arbitrary code execution via Man-in-the-Middle (MITM) or server compromise.
date: "2026-10-30T01:09:54Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:red_hat:openshift_ansible:*:*:*:*:*:*:*:*
vendors:
  - Red Hat
products:
  - openshift-ansible
cves:
  - id: CVE-2026-92092
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92092
---

A security flaw exists in the `run` script of the `openshift-ansible` installer container. The script downloads and executes remote inventory and dynamic scripts without integrity verification. A remote attacker, by performing a Man-in-the-Middle (MITM) attack or compromising the HTTP server providing these scripts, could substitute an arbitrary executable. This executable would run with the installer's user ID and full cluster-provisioning privileges, leading to arbitrary code execution.
