# DNS Threat Platform

Enterprise-grade DNS threat intelligence, ingestion, and enforcement. This platform centralizes STIX/TAXII feeds and curated sources (OTX, MISP) to turn threat data into real-time DNS protections with measurable impact.

## Why It Matters
- **DNS is the earliest control point** for blocking phishing, malware, and data exfiltration.
- **Threat feeds are fragmented** across platforms and formats, delaying response.
- **Security teams need proof** that intel reduces risk and exposure.

This platform solves those gaps with a unified pipeline from intelligence ingestion to automated enforcement.

## What It Does
- Ingests threat intel from **STIX/TAXII**, **OTX**, and **MISP**
- Normalizes into **STIX 2.1 indicators**
- Syncs indicators into **policy enforcement**
- Exposes a clean **API surface** for querying and automation

## Product Highlights
- **Multi-source ingestion**: TAXII 2.1 pulls, OTX exports, MISP restSearch
- **Normalized data model**: single STIX collection for indicators
- **Fast enforcement loop**: indicators sync to DNS rules in seconds
- **Operational visibility**: collections, objects, and manifests via API

## Proof Points (Replace With Validated Metrics)
Use this section in decks and one-pagers. Replace the placeholders once you have measured numbers.

- **Threat coverage**: `[[X]]` indicators ingested across `[[Y]]` sources
- **Update velocity**: `[[X]]` new indicators/hour at peak
- **Time-to-block**: `[[X]]` seconds from ingest to enforcement
- **False-positive rate**: `[[X]]%` after tuning
- **Blocked queries**: `[[X]]` per day across `[[Y]]` protected endpoints
- **Analyst time saved**: `[[X]]` hours/month (measured)

## Competitive Positioning
- **Unified pipeline**: consolidates disparate feeds into a single source of truth
- **Actionable outcomes**: not just intel storage—enforces at DNS
- **Open standards**: STIX 2.1 and TAXII 2.1 compatible

## Architecture (High-Level)
- **API**: FastAPI service exposing TAXII 2.1 and internal feed endpoints
- **Storage**: SQLite STIX object store (pluggable to Postgres)
- **Feeds**: OTX and MISP ingestion with STIX normalization
- **Enforcement**: indicator-to-rule synchronization pipeline

## API Endpoints (Summary)
- `POST /feeds/otx/pull` — Pull OTX domain indicators
- `POST /feeds/misp/pull` — Pull MISP domain indicators
- `POST /taxii2/pull` — Pull from TAXII collection
- `GET /stix/objects` — List STIX objects
- `POST /stix/sync` — Sync indicators to enforcement rules

## Pitch Statement
**DNS Threat Platform** is a real-time intelligence and enforcement layer that translates disparate threat feeds into immediate protection. It gives security teams both the coverage they need and the metrics leadership demands.

## Next Steps
- Add validated performance metrics
- Capture customer outcomes and incident reductions
- Package with deployment options (Docker/K8s)
