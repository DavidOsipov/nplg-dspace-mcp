# ADR-002: Basic query plus typed filters, without a Lucene parser

**Status:** PROPOSED / NON-EXECUTABLE — contract approval required

**Date:** 2026-09-02

## Context

The anonymous `alpic-metadata` profile needs useful NPLG Discovery search
without exposing raw DSpace/Solr field syntax. The earlier design considered
Luqum as a local AST guardrail. The product need is narrower: a basic main
query plus typed positive filters can cover the first release.

A local parser cannot establish NPLG analyzer, stemming, stop-word, scoring,
or match semantics. It can only apply a local admission policy. Adding a
Lucene parser would therefore create a second parser boundary without making
the upstream DSpace 5.5/Solr interpretation authoritative or observable.

## Decision

The initial search syntax profile is explicitly **basic query plus typed
positive filters**.

- Do not add Luqum, PLY, another Lucene parser, an AST model, or a handwritten
  Lucene grammar.
- Pydantic validates one bounded basic query string. The admitted shapes are
  plain text or one whole quoted phrase.
- The validated, whitespace-canonicalized `submitted_query` is sent upstream
  unchanged. There is no AST serialization, compatibility query, or query
  rewrite.
- Field selection, positive operators, issue-year ranges, sort, and order use
  closed wire `Literal` values compiled to server-owned constants after
  validation.
- Boolean, grouping, unary, and wildcard syntax are not supported in the
  initial profile. Whether to support them, and whether that then justifies a
  parser, is a separate post-stability product and dependency decision.

The normative query admission and approval corpus live in
[`../superpowers/specs/2026-09-02-anonymous-metadata-v2-contract.md`](../superpowers/specs/2026-09-02-anonymous-metadata-v2-contract.md).

## Luqum evaluation

Luqum is not intrinsically unsuitable software. It is a poor fit for this
narrow initial contract:

- Luqum 1.0.0 depends on PLY and is based on a Lucene 3.6 grammar, which does
  not prove equivalence to NPLG's deployed DSpace/Solr configuration.
- Its documented default parser is not thread-safe; the thread helper is
  described by its own documentation as only “hopefully” thread-safe.
- Published support evidence covers Python 3.12 and 3.13, while the project
  also targets Python 3.14. Open issues describe parser-table behavior on
  immutable installs and newer Python versions.
- Allowed and forbidden wildcard placement can share the same broad AST node,
  so a separate lexical policy remains necessary.
- Parser exceptions and tokens add input-derived error/logging surface that
  the public service must suppress.
- The current contract deliberately rejects all free-form Boolean, grouping,
  unary, and wildcard syntax, so no AST information is needed at runtime.

No registered Luqum or PLY advisory was found during the 2026-09-02 review.
That is not evidence of a security audit or proof of safety.

## Consequences

### Positive

- No new runtime dependency or parser differential is introduced.
- The service never changes accepted query intent by rendering an AST.
- Typed filters remain the only public route to reviewed DSpace fields,
  operators, and ranges.
- Parser-library upgrades cannot silently change the approved accept/reject
  corpus.

### Trade-off

The initial lexical policy intentionally rejects some ordinary punctuation
that could also be interpreted as Lucene syntax. This includes `AC/DC`,
`What happened?`, `Georgia (1918–1921)`, `Question!`, and `A/B testing`.
That product trade-off must be approved with the wire contract; it is not
described as an upstream limitation.

### Reconsideration trigger

Revisit this ADR only when a concrete client workflow needs free-form Boolean,
grouping, unary, or suffix-wildcard queries. A post-stability proposal must
compare a maintained parser with the option of keeping those constructs
unsupported, test the complete accept/reject corpus on every supported Python
version, and retain the rule that an AST is never rendered for upstream
submission.

## Rejected alternatives

- **Luqum in the initial profile:** more dependency and differential risk than
  the admitted syntax requires.
- **Another Lucene parser in the initial profile:** the same YAGNI problem
  without evidence of a better fit.
- **Handwritten mini-parser:** duplicates a query grammar while pretending not
  to be a parser.
- **Raw query passthrough:** admits field syntax, ranges, and other unsupported
  constructs into a public fixed-origin service.

## Evidence reviewed

- [Luqum 1.0.0 package metadata](https://pypi.org/project/luqum/1.0.0/)
- [Luqum parser API and thread-safety note](https://luqum.readthedocs.io/en/latest/api.html)
- [Luqum parser source](https://github.com/jurismarches/luqum/blob/1.0.0/luqum/parser.py)
- [Immutable parser-table issue 114](https://github.com/jurismarches/luqum/issues/114)
- [Python-version parser-table issue 115](https://github.com/jurismarches/luqum/issues/115)
- [NPLG search help](https://dspace.nplg.gov.ge/help/index.html)
- [Official DSpace 5.5 Discovery request processor](https://github.com/DSpace/DSpace/blob/dspace-5.5/dspace-jspui/src/main/java/org/dspace/app/webui/discovery/DiscoverySearchRequestProcessor.java)
