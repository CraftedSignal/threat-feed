---
title: Absinthe GraphQL Atom Table Exhaustion Vulnerability
slug: 2026-05-absinthe-atom-dos
description: Absinthe versions 1.5.0 before 1.10.2 are vulnerable to a denial-of-service attack (CVE-2026-42793) due to unbounded atom creation when parsing GraphQL SDL documents, allowing an attacker to exhaust the Erlang VM's atom table and crash the entire node by submitting a crafted document with numerous unique directive names.
date: "2026-05-14T13:10:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - graphql
  - atom-table-exhaustion
vendors:
  - Erlang
products:
  - absinthe (>= 1.5.0, < 1.10.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-42793
    epss: 0.00048
references:
  - https://github.com/advisories/GHSA-qf4g-9fqq-mmm7
  - https://github.com/absinthe-graphql/absinthe/commit/d0eae7764520d4e8e5dfff619068c0de911aec33
rules:
  - title: Detect Absinthe GraphQL Atom Table Exhaustion Attempt
    description: Detects CVE-2026-42793 exploitation attempt — identifies suspicious GraphQL payloads containing numerous unique directive definitions based on HTTP request logs by counting the number of 'directive @' occurrences.
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - webserver
  - title: Detect High Atom Count in Erlang VM
    description: Detects a high number of atoms in the Erlang VM, potentially indicating an atom exhaustion attack.
    platform: sigma
    severity: medium
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Absinthe, a GraphQL toolkit for Elixir, is susceptible to a denial-of-service vulnerability (CVE-2026-42793) affecting versions 1.5.0 prior to 1.10.2. The vulnerability stems from the way Absinthe parses GraphQL SDL documents. Specifically, every `directive @<name>` definition is converted into a newly created atom without any allow-list or length cap. Since Erlang atoms are never garbage-collected and the BEAM VM has a finite atom table (approximately 1,048,576 atoms), an attacker can exhaust this table by sending a specially crafted GraphQL document containing a large number of unique directive names. The attack requires no authentication and impacts all workloads on the Erlang node.

## Attack Chain

1. An attacker crafts a GraphQL SDL document containing a large number of unique directive definitions (e.g., `directive @randomName1 on FIELD`, `directive @randomName2 on FIELD`, etc.).
2. The attacker sends an HTTP POST request to the `/graphql` endpoint of an application using `absinthe_plug`.
3. `Plug.Parsers` processes the request and parses the GraphQL document using `Absinthe.Plug.Parser`.
4. `Absinthe.Phase.Parse` is invoked to parse the SDL.
5. `Absinthe.Blueprint.Draft.convert/2` processes the parsed SDL.
6. For each `DirectiveDefinition` node in the SDL, `Macro.underscore(node.name) |> String.to_atom()` is called in `lib/absinthe/language/directive_definition.ex:27`, creating a new atom from the directive name. This also occurs in `lib/absinthe/language/enum_type_definition.ex:23`, `lib/absinthe/language/field_definition.ex:27`, etc.
7. If the attacker-controlled document contains enough unique directive names (approaching 1 million), the BEAM VM's atom table becomes exhausted.
8. Subsequent attempts to create new atoms result in a crash of the entire Erlang node, causing a denial of service.

## Impact

Successful exploitation of this vulnerability results in a denial-of-service condition, where the entire Erlang node crashes due to atom-table exhaustion. This impacts not only the Absinthe-based application but also any other Erlang-based workloads running on the same VM. The vulnerability can be triggered without authentication and requires only the ability to send a specially crafted GraphQL document to an exposed endpoint.

## Recommendation

*   Upgrade to Absinthe version 1.10.2 or later to patch CVE-2026-42793.
*   Implement input validation and sanitization on any endpoint that accepts GraphQL SDL documents to prevent attackers from injecting a large number of unique directive names.
*   Monitor the Erlang VM's atom count using `:erlang.system_info(:atom_count)` and alert if it approaches the limit (approximately 1,048,576). This can provide early warning of an attempted atom-table exhaustion attack.
*   Deploy the Sigma rule "Detect Absinthe GraphQL Atom Table Exhaustion Attempt" to identify suspicious GraphQL payloads containing numerous unique directive definitions based on HTTP request logs.
