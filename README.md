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

This connects to both environments via the SOAP API, fetches all queries from each, and matches them by language, group, and query name. When a query is overridden more than once under the same name in the target (e.g. a corporate default plus one or more team/project-level overrides, each with its own QueryId), every source override of that name is mapped to the target's **highest-level** override — the corporate default, or if there's no corporate-level entry, whichever team-level override is closest to the root team — rather than to whatever target team/project happens to share the source override's scope. Source and target team/project structures aren't guaranteed to correspond 1:1, so matching scope-to-scope could pick an unrelated override; the top of the hierarchy is the one every project inherits from unless specifically customized, making it the one safe, predictable choice. Each override's owning team/project ID is still resolved to its full path (via the REST/OData APIs) purely for the `INFO`/`NOTE` diagnostic output, not for choosing the match. The output is written to `mapping.json` (or the path set in `OUTPUT_FILE`).

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
7. Match each source result to a target result — by computed similarity ID when `--similarity-calculator` is set (comparing the calculator's output against the target scan's actual similarity IDs, the purpose-built mechanism for identifying the same finding across scans), falling back to path-node comparison (source file/line/object, destination file/line/object, number of nodes) otherwise or when no similarity-ID match is found.
8. Apply all triage changes to the matching results in the target scan.
9. Write a CSV report summarising every result: matched, not found, missing query, or error.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--project NAME_OR_ID` | *(one of `--project` / `--project-list` required)* | Full project name (`CxServer\ProjectName`) or numeric project ID |
| `--project-list NAME_OR_ID,...` | *(one of `--project` / `--project-list` required)* | Comma-separated list of project names/IDs to migrate one after another |
| `--mapping PATH` | `mapping.json` | Path to the query mapping file produced by `generate_mapping.py` |
| `--output PATH` | `triage_migration.csv` (or `similarity_comparison.csv` with `--compare-triages`) | Path for the output CSV report |
| `--similarity-calculator PATH` | *(none)* | Path to `SimilarityCalculator.exe` (Windows only; optional normally, **required** with `--compare-triages`) |
| `--sim-version 0\|1\|2` | `0` (or `SIM_ID_VERSION` env var) | Version value passed as `SimilarityCalculator.exe`'s final positional argument |
| `--dry-run` | *(off)* | Fetch and match everything but skip uploading any changes |
| `--compare-triages` | *(off)* | Read-only mode — compare computed vs. actual target similarity IDs instead of migrating triage data (see below) |

### Example — dry run first

Always do a dry run before committing changes to confirm that results are matching as expected:

```bash
python3 migrate_triages.py --project "CxServer\MyProject" --dry-run
```

Review the CSV output, then run without `--dry-run` to apply the changes:

```bash
python3 migrate_triages.py --project "CxServer\MyProject"
```

### Example — migrate multiple projects

Pass `--project-list` instead of `--project` to migrate several projects in one run. Each project is processed fully (find, match, upload) in turn before moving to the next; the CSV report accumulates rows for all of them, distinguished by `source_project_id`/`target_project_id`:

```bash
python3 migrate_triages.py --project-list "CxServer\MyProject,CxServer\OtherProject,101"
```

If a project in the list can't be found (or has no finished scans), the script logs an error, skips it, and continues with the rest of the list; it exits non-zero at the end if any project failed.

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
- **NOT_FOUND** — no result in the target scan matched by computed similarity ID (if available) or source path nodes.
- **NO_QUERY** — the source query has no entry in `mapping.json` and was not found by name in the target query library.
- **ERROR** — the source query ID was not found in the query collection.

---

## `--compare-triages` (similarity ID comparison)

A read-only diagnostic mode that checks whether `SimilarityCalculator.exe` reproduces the similarity IDs CxSAST actually assigned in the target scan — useful for validating the calculator setup before trusting it to compute similarity IDs during a real migration. It makes **no changes** to either environment.

```bash
python3 migrate_triages.py --project "CxServer\MyProject" --compare-triages --similarity-calculator C:\path\to\SimilarityCalculator.exe
```

For every result in each project's latest scans (not just triaged ones — the full scan, to give the broadest possible check), it:

1. Pulls similarity IDs from the source scan (OData).
2. Resolves the matching target query (via `mapping.json`, with the same duplicate-query fallback used in the main migration) and computes a target similarity ID with `SimilarityCalculator.exe`.
3. Pulls similarity IDs from the target scan (OData) and pairs each source result with its target counterpart using the same path-node matching (`match_result`) the main migration uses.
4. Writes a CSV comparing all three IDs.

`--similarity-calculator` is **required** for this mode (the whole point is to validate it) and is still Windows-only.

### Comparison CSV columns

| Column | Description |
|--------|-------------|
| `status` | `MATCHED`, `NOT_FOUND`, `NO_QUERY`, or `ERROR` |
| `source_similarity_id` | Similarity ID from the source scan (OData) |
| `computed_similarity_id` | Similarity ID computed by `SimilarityCalculator.exe` from the source's path node data + resolved target query ID |
| `target_similarity_id` | Similarity ID actually present on the matched target result (OData) |
| `matches` | `True` if `computed_similarity_id` equals `target_similarity_id` (and a computed ID was produced), `False` otherwise |
| `Calculator_Command` | The exact `SimilarityCalculator.exe` command run for this row (quoted for copy-paste), so a mismatch can be reproduced and debugged manually outside the script |

Default output file is `similarity_comparison.csv` (override with `--output`).

---

## Notes

- **Query mapping is required.** The mapping file tells the script how query IDs differ between environments. If a query is in the source but missing from `mapping.json`, the result is skipped with status `NO_QUERY`. Re-run `generate_mapping.py` if queries have been added or customised since the last mapping was generated.
- **Only the latest finished scan is used** for both source and target projects.
- **Triage is uploaded via `PATCH /cxrestapi/sast/scans/{scanId}/results/{pathId}/labels`**, one call per result (or per historical change — see below). This is the endpoint that actually applies the change; an older SOAP-based approach (`UpdateSetOfResultState`) and a bulk REST variant (`PATCH .../results` with `{resultId, stateId, comment}`) were both found to return success without the state actually changing on the target. Each call only includes the field(s) (`state`, `severity`, `userAssignment`) that actually changed at that step, plus `comment` (always present, even if empty) — the target logs a distinct audit entry for every field present in the request, even when the value sent matches what's already there, so unchanged fields are omitted rather than resent.
- **Comments** are built from the full comment history (via `GetPathCommentsHistory`). Any comments present in the source but absent from the target are consolidated into a single string (preserving the original author/timestamp text) and attached to the last `/labels` call for that result, so the comment always lands even when state/severity/assignee are unchanged.
- **State/severity/assignee history** is replayed in chronological order — one `/labels` call per historical change, carrying forward the latest known values each time — when the OData `ResultTriageHistories` endpoint is available. If it is not (older CxSAST versions), only the final values are applied in a single call.
- **`SimilarityCalculator.exe`** is a Windows-only binary and is optional. It's called with 12 plain positional arguments — `filename, name, line, column, methodLine` for the source node, the same five for the destination node, the resolved target query ID, and the sim-ID version (`0`, `1`, or `2`, via `--sim-version` or the `SIM_ID_VERSION` env var) — matching Checkmarx's own reference caller ([sast-to-ast-export](https://github.com/Checkmarx/sast-to-ast-export/blob/master/internal/integration/similarity/similarity_id_calculator.go)). There is no `--simIdVersion` flag. Column and method-line come from the **source** scan's own `GetResultPathsForQuery` SOAP call (per source QueryId) — `GetResultsForScan`'s `SourceLine`/`DestLine` etc. don't include them — taking the first and last node of each result's path. `filename` must be a real local file, not just the recorded folder/filename string, so its actual content is downloaded first via `GetSourcesByScanID` (remote path = plain backslash concatenation of `SourceFolder`+`SourceFile`, preserving the folder's own leading backslash — confirmed by live testing; the per-item `IsSuccesfull` flag in the response is **not** a reliable fetch-status indicator, an empty `Source` string is). On non-Windows platforms the calculator step is automatically skipped.
- **Matching prefers computed similarity ID over path nodes** when `--similarity-calculator` is set: for each source result, the computed similarity ID is compared against each target-query candidate's actual similarity IDs first (the mechanism CxSAST itself uses to identify the same finding across scans), falling back to path-node comparison only if no similarity-ID match is found. `--compare-triages` deliberately matches by path nodes only, since its purpose is validating the calculator independently — it can't also use the calculator's own output to decide what counts as a match.
