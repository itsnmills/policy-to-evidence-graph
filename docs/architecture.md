# Architecture

The tool is organized around a deterministic pipeline:

1. Ingest local files into normalized records
2. Map evidence to controls
3. Compute control readiness states
4. Generate matrix + gaps + snapshot comparisons
5. Export packet and dashboard data

The graph is intentionally lightweight and local-first.
