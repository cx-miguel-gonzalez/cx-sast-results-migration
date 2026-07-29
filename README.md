# CxSAST Results Migration

Migrate triage data (states, severities, comments, and assigned users) from projects in one Checkmarx SAST environment to another.

## Overview

Migration is a two-step process:

1. **`generate_mapping.py`** — Compares query libraries across both environments and produces a `mapping.json` file that maps source query IDs to their corresponding target query IDs.
2. **`migrate_triages.py`** — Uses that mapping file to copy all triage data from the latest scan of a source project into the matching project on the target environment.

You must run `generate_mapping.py` and have a valid `mapping.json` before running `migrate_triages.py`.

## Prerequisites

- Python 3.9+
- Access to both source and target CxSAST environments (HTTP/HTTPS)

Install dependencies:

```bash
python3 -m pip install -r requirements.txt
```

> Use `python3 -m pip` (not `pip` or `pip3`) to ensure packages are installed for the same Python interpreter that runs the scripts.

## Configuration

Copy the example environment file and fill in your credentials:

```bash
cp .env.example .env
```

Edit `.env`:

```
SOURCE_URL=http://<source-host>
SOURCE_USERNAME=admin
SOURCE_PASSWORD=<password>

TARGET_URL=http://<target-host>
TARGET_USERNAME=admin
TARGET_PASSWORD=<password>

VERIFY_SSL=false
OUTPUT_FILE=mapping.json
```

Set `VERIFY_SSL=true` when both environments have valid TLS certificates.

---

## Step 1 — Generate the query ID mapping

```bash
python3 generate_mapping.py
```

This connects to both environments via the SOAP API, fetches all queries from each, and matches them by language, group, and query name. The output is written to `mapping.json` (or the path set in `OUTPUT_FILE`).

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--output PATH` | `mapping.json` | Path to write the mapping file |

At the end of the run the script prints how many queries were matched, how many exist only in the source, and how many exist only in the target.

---

## Step 2 — Migrate triage data

```bash
python3 migrate_triages.py --project "CxServer\MyProject"
```

The script will:

1. Look up the source project by full name (`TeamPath\ProjectName`) or numeric ID.
2. Pull the latest finished scan from the source project.
3. Fetch all triaged results (state, severity, comments, assigned user) from that scan.
4. Retrieve the full triage history for each result — all state changes and all comments, not just the most recent ones.
5. Find the matching project in the target environment by the same full name.
6. Pull the latest finished scan from the target project.
7. Match each source result to a target result using path-node comparison (source file/line/object, destination file/line/object, number of nodes).
8. Apply all triage changes to the matching results in the target scan.
9. Write a CSV report summarising every result: matched, not found, missing query, or error.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--project NAME_OR_ID` | *(required)* | Full project name (`CxServer\ProjectName`) or numeric project ID |
| `--mapping PATH` | `mapping.json` | Path to the query mapping file produced by `generate_mapping.py` |
| `--output PATH` | `triage_migration.csv` | Path for the output CSV report |
| `--similarity-calculator PATH` | *(none)* | Path to `SimilarityCalculator.exe` (Windows only, optional) |
| `--sim-version 0\|1\|2` | `0` | Version argument passed to `SimilarityCalculator.exe` |
| `--dry-run` | *(off)* | Fetch and match everything but skip uploading any changes |

### Example — dry run first

Always do a dry run before committing changes to confirm that results are matching as expected:

```bash
python3 migrate_triages.py --project "CxServer\MyProject" --dry-run
```

Review the CSV output, then run without `--dry-run` to apply the changes:

```bash
python3 migrate_triages.py --project "CxServer\MyProject"
```

### CSV report columns

| Column | Description |
|--------|-------------|
| `status` | `MATCHED`, `NOT_FOUND`, `NO_QUERY`, or `ERROR` |
| `source_project_id` / `target_project_id` | Numeric project IDs |
| `source_scan_id` / `target_scan_id` | Scan IDs used |
| `query_name` / `language` / `group` | Query metadata |
| `source_path_id` / `target_path_id` | Result path IDs |
| `source_similarity_id` / `target_similarity_id` | Similarity IDs from OData |
| `computed_similarity_id` | Similarity ID from `SimilarityCalculator.exe` (if used) |
| `source_state` / `source_severity` / `source_comment` | Triage values from the source |
| `detail` | Error or informational message for non-matched results |

### Status values

- **MATCHED** — result was found in the target scan and triage data will be applied.
- **NOT_FOUND** — no result in the target scan matched the source path nodes.
- **NO_QUERY** — the source query has no entry in `mapping.json` and was not found by name in the target query library.
- **ERROR** — the source query ID was not found in the query collection.

---

## Notes

- **Query mapping is required.** The mapping file tells the script how query IDs differ between environments. If a query is in the source but missing from `mapping.json`, the result is skipped with status `NO_QUERY`. Re-run `generate_mapping.py` if queries have been added or customised since the last mapping was generated.
- **Only the latest finished scan is used** for both source and target projects.
- **Comments** are migrated using the full comment history (via `GetPathCommentsHistory`). Any comments present in the source but absent from the target are consolidated into a single appended comment preserving the original author and timestamp text.
- **State history** is replayed in chronological order when the OData `ResultTriageHistories` endpoint is available. If it is not (older CxSAST versions), the final state is applied instead.
- **`SimilarityCalculator.exe`** is a Windows-only binary and is optional. It computes target similarity IDs from path node data and mapped query IDs. On non-Windows platforms it is automatically skipped.
