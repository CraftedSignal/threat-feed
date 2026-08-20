---
title: NoSQL Operator Injection in LangGraph MongoDB Libraries
slug: 2026-08-langchain-mongodb-nosql-injection
description: A NoSQL injection vulnerability in the langgraph-checkpoint-mongodb and langgraph-store-mongodb libraries allows authenticated attackers to bypass tenant isolation boundaries and exfiltrate sensitive data via injected MongoDB query operators.
date: "2026-08-20T19:15:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - nosql-injection
  - data-exposure
  - langchain
  - cve-2026-55253
vendors:
  - LangChain
products:
  - langgraph-checkpoint-mongodb
  - langgraph-store-mongodb
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A NoSQL injection issue exists in the langgraph-checkpoint-mongodb and langgraph-store-mongodb libraries, specifically within the MongoDBSaver.list() and MongoDBStore.search() methods.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: In multi-tenant environments, this allows an attacker to bypass data isolation boundaries and access sensitive checkpoint or store data belonging to other tenants.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-533j-2v4q-mw5h
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55253
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Application Security
  immediate_actions:
    - action: Upgrade affected packages to the patched versions.
      owner: Application Security
      due: 48h
      evidence: Upgrade to the version of langgraph-checkpoint-mongodb and langgraph-store-mongodb.
  mitigation_plan:
    - priority: immediate
      action: Sanitize user input before passing to filter arguments.
      owner: Application Security
      addresses: CVE-2026-55253
      evidence: In your application code, before passing any user-controlled input to the filter parameter, remove or escape MongoDB Query metacharacters such as $.
---

The LangGraph MongoDB integration libraries (langgraph-checkpoint-mongodb and langgraph-store-mongodb) are vulnerable to NoSQL operator injection (CVE-2026-55253). This vulnerability stems from inadequate sanitization of the 'filter' parameter passed to the 'MongoDBSaver.list()' and 'MongoDBStore.search()' methods. Because these methods allow caller-supplied input to be embedded directly into database queries, an authenticated attacker can inject MongoDB operator keys prefixed with '$'. In multi-tenant applications where these methods are relied upon for data isolation, an attacker can manipulate the query logic to access or exfiltrate checkpoint or store data belonging to other tenants. This flaw impacts all versions of langgraph-checkpoint-mongodb prior to 0.3.0 and langgraph-store-mongodb prior to 0.4.0. Defenders should audit application code to ensure that any 'filter' parameter passed to these libraries is strictly validated and stripped of characters associated with MongoDB query operators.

## Impact

Successful exploitation of this vulnerability results in a loss of data confidentiality across tenant boundaries. Attackers can gain unauthorized read access to state, checkpoints, or stored data belonging to other users or organizations. Given the reliance on these libraries for agentic workflows and memory storage, the compromise allows for the mass exfiltration of sensitive conversational history or application state.

## Recommendation

* Upgrade 'langgraph-checkpoint-mongodb' to version 0.3.0 or later and 'langgraph-store-mongodb' to version 0.4.0 or later to patch CVE-2026-55253.
* Audit application code to identify instances where user-controlled input (e.g., HTTP query parameters or request body fields) is passed directly to the 'filter' argument of 'MongoDBSaver.list()', 'MongoDBSaver.alist()', or 'MongoDBStore.search()'.
* Implement strict input validation or sanitization routines on the server side to remove or escape the '$' character from any user-provided data before it is incorporated into database filter objects.
