---
brief_id: brief-2026-11-11-apache-storm-logviewer-symlink
event_id: brief-2026-11-11-apache-storm-logviewer-symlink
revision: 1
activity_at: "2026-11-11T03:38:33Z"
title: 'Apache Storm: Logviewer follows worker symlinks across topology ACLs (CVE-2026-124495)'
slug: 2026-11-apache-storm-logviewer-symlink
description: When workers run as the topology owner, the Apache Storm Logviewer serves files that a worker has placed in its own log directory as links to other files, allowing users who can submit topologies to read other users' worker logs and files accessible to the Logviewer process.
date: "2026-11-11T03:38:33Z"
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
products:
  - org.apache.storm:storm-webapp (3.0.0 before 3.2.0)
cves:
  - id: CVE-2026-124495
    kev_status: unknown
references:
  - https://seclists.org/oss-sec/2026/q4/653
---

When workers run as the topology owner, the Logviewer serves files that a worker has placed in its own log directory as links to other files. A user who is allowed to submit topologies can read the worker logs of other users' topologies, and other files the Logviewer process can read.
