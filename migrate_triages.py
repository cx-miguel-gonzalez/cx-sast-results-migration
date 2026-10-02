#!/usr/bin/env python3
"""
migrate_triages.py

Copy triage data (state, severity, comment, assigned user) from the latest scan
of a source SAST project to the matching project/scan in the target environment.

Steps:
  1. Find source project by name or ID
  2. Get latest finished scan for source project
  3. Fetch source results via SOAP + SimilarityIds via OData
  4. Optionally compute new SimilarityIds via SimilarityCalculator.exe (Windows only)
  5. Write CSV: source_similarity_id, target_similarity_id, match status, triage details
  6. Find target project by source project full name
  7. Get latest finished scan for target project
  8. Fetch target results via SOAP + SimilarityIds via OData
  9. Match each triaged source result to a target result by path nodes
 10. Upload triages (state, severity, comment, assigned user) to target scan

Usage:
    python3 migrate_triages.py --project "MyProject" [options]
    python3 migrate_triages.py --project 42 [options]
    python3 migrate_triages.py --project "MyProject" --dry-run
"""

import argparse
import csv
import json
import os
import platform
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv
from requests import Session
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from zeep import Client, Settings
from zeep.transports import Transport

load_dotenv()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TOKEN_PATH    = "/cxrestapi/auth/identity/connect/token"
CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"

SOAP_SCOPE    = "offline_access sast_api"
SOAP_CLIENT   = "resource_owner_sast_client"
REST_SCOPE    = "sast_rest_api"
REST_CLIENT   = "resource_owner_client"
ODATA_SCOPE   = "access_control_api sast_api"
ODATA_CLIENT  = "resource_owner_sast_client"

WSDL_PATH     = "/CxWebInterface/Portal/CxWebService.asmx?wsdl"
ODATA_BASE    = "/Cxwebinterface/odata/v1"
REST_BASE     = "/cxrestapi"

CSV_FIELDS = [
    "status",
    "source_project_id", "source_scan_id",
    "target_project_id", "target_scan_id",
    "query_name", "language", "group",
    "source_path_id", "target_path_id",
    "source_similarity_id", "target_similarity_id", "computed_similarity_id",
    "source_state", "source_severity", "source_comment",
    "detail",
]


# ---------------------------------------------------------------------------
# Auth & client factory
# ---------------------------------------------------------------------------

def _get_token(base_url: str, username: str, password: str, scope: str,
               client_id: str, verify: bool) -> str:
    resp = requests.post(
        base_url.rstrip("/") + TOKEN_PATH,
        data={
            "username": username,
            "password": password,
            "grant_type": "password",
            "scope": scope,
            "client_id": client_id,
            "client_secret": CLIENT_SECRET,
        },
        verify=verify,
        timeout=30,
    )
    resp.raise_for_status()
    d = resp.json()
    return d["token_type"] + " " + d["access_token"]


def _make_soap_client(base_url: str, token: str, verify: bool) -> Client:
    settings = Settings(
        strict=False, force_https=False, xml_huge_tree=True,
        extra_http_headers={"Authorization": token},
    )
    session = Session()
    session.verify = verify
    client = Client(
        wsdl=base_url.rstrip("/") + WSDL_PATH,
        transport=Transport(session=session),
        settings=settings,
    )
    client.transport.session.verify = verify
    return client


# ---------------------------------------------------------------------------
# SastEnv — lazy connection wrapper for one environment
# ---------------------------------------------------------------------------

class SastEnv:
    def __init__(self, base_url: str, username: str, password: str, verify: bool):
        self.url      = base_url.rstrip("/")
        self._user    = username
        self._pass    = password
        self.verify   = verify
        self._soap_tk = None
        self._rest_tk = None
        self._odata_tk = None
        self._soap    = None

    # -- SOAP ----------------------------------------------------------------

    @property
    def soap(self) -> Client:
        if self._soap is None:
            self._soap_tk = _get_token(self.url, self._user, self._pass, SOAP_SCOPE, SOAP_CLIENT, self.verify)
            self._soap = _make_soap_client(self.url, self._soap_tk, self.verify)
        return self._soap

    # -- REST ----------------------------------------------------------------

    def rest_get(self, path: str) -> object:
        if not self._rest_tk:
            self._rest_tk = _get_token(self.url, self._user, self._pass, REST_SCOPE, REST_CLIENT, self.verify)
        return self._rest_get_with_token(path)

    def _rest_get_with_token(self, path: str) -> object:
        resp = requests.get(
            self.url + path,
            headers={"Authorization": self._rest_tk, "Accept": "application/json"},
            verify=self.verify, timeout=60,
        )
        if resp.status_code == 401:
            self._rest_tk = _get_token(self.url, self._user, self._pass, REST_SCOPE, REST_CLIENT, self.verify)
            resp = requests.get(
                self.url + path,
                headers={"Authorization": self._rest_tk, "Accept": "application/json"},
                verify=self.verify, timeout=60,
            )
        resp.raise_for_status()
        return resp.json() if resp.content and len(resp.content) > 2 else []

    def rest_patch(self, path: str, payload: object) -> Tuple[int, object]:
        """
        PATCH request. Returns (status_code, parsed_body) WITHOUT raising on a
        non-2xx status — callers need the raw status/body for diagnostics,
        since CxSAST's result-update endpoints have been seen to return a
        success-looking status without actually applying the change.
        """
        if not self._rest_tk:
            self._rest_tk = _get_token(self.url, self._user, self._pass, REST_SCOPE, REST_CLIENT, self.verify)
        headers = {
            "Authorization": self._rest_tk,
            "Accept": "application/json;v=1.0",
            "Content-Type": "application/json;v=1.0",
        }
        resp = requests.patch(self.url + path, headers=headers, json=payload, verify=self.verify, timeout=60)
        if resp.status_code == 401:
            self._rest_tk = _get_token(self.url, self._user, self._pass, REST_SCOPE, REST_CLIENT, self.verify)
            headers["Authorization"] = self._rest_tk
            resp = requests.patch(self.url + path, headers=headers, json=payload, verify=self.verify, timeout=60)
        try:
            body = resp.json() if resp.content else None
        except ValueError:
            body = resp.text
        return resp.status_code, body

    # -- Access-control REST (same token as OData) ---------------------------

    def access_rest_get(self, path: str) -> object:
        """GET authenticated with access_control_api scope (for /cxrestapi/auth/... endpoints)."""
        if not self._odata_tk:
            self._odata_tk = _get_token(self.url, self._user, self._pass, ODATA_SCOPE, ODATA_CLIENT, self.verify)
        resp = requests.get(
            self.url + path,
            headers={"Authorization": self._odata_tk, "Accept": "application/json"},
            verify=self.verify, timeout=60,
        )
        if resp.status_code == 401:
            self._odata_tk = _get_token(self.url, self._user, self._pass, ODATA_SCOPE, ODATA_CLIENT, self.verify)
            resp = requests.get(
                self.url + path,
                headers={"Authorization": self._odata_tk, "Accept": "application/json"},
                verify=self.verify, timeout=60,
            )
        resp.raise_for_status()
        return resp.json() if resp.content and len(resp.content) > 2 else []

    # -- OData (paginated) ---------------------------------------------------

    def odata_get_all(self, path: str, page_size: int = 1000) -> list:
        if not self._odata_tk:
            self._odata_tk = _get_token(self.url, self._user, self._pass, ODATA_SCOPE, ODATA_CLIENT, self.verify)
        results = []
        skip = 0
        sep = "&" if "?" in path else "?"
        while True:
            url = f"{self.url}{path}{sep}$top={page_size}&$skip={skip}"
            resp = requests.get(
                url,
                headers={
                    "Authorization": self._odata_tk,
                    "Accept": "application/json",
                    "Content-Type": "application/json;v=1.0",
                },
                verify=self.verify, timeout=120,
            )
            if resp.status_code == 401:
                self._odata_tk = _get_token(self.url, self._user, self._pass, ODATA_SCOPE, ODATA_CLIENT, self.verify)
                resp = requests.get(url, headers={
                    "Authorization": self._odata_tk,
                    "Accept": "application/json",
                    "Content-Type": "application/json;v=1.0",
                }, verify=self.verify, timeout=120)
            resp.raise_for_status()
            page = resp.json().get("value", [])
            results.extend(page)
            if len(page) < page_size:
                break
            skip += page_size
        return results


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _get_team_map(env: SastEnv) -> Dict[int, str]:
    """Return {teamId: fullTeamPath} using GET /cxrestapi/auth/teams.

    The REST API returns Unix-style paths ("/CxServer/Team"); we convert them
    to the backslash form used by the SAST UI ("CxServer\\Team").
    """
    teams = env.access_rest_get(f"{REST_BASE}/auth/teams")
    result: Dict[int, str] = {}
    for t in (teams if isinstance(teams, list) else []):
        team_id = t.get("id")
        full_name = (t.get("fullName") or t.get("name") or "").lstrip("/").replace("/", "\\")
        if team_id is not None:
            result[team_id] = full_name
    return result


def _attach_full_names(projects: list, team_map: Dict[int, str]) -> None:
    """Add '_FullName' key (TeamPath\\ProjectName) to each project dict in-place."""
    for p in projects:
        team_path = team_map.get(p.get("OwningTeamId"), "")
        p["_FullName"] = f"{team_path}\\{p['Name']}" if team_path else p["Name"]


def get_project(env: SastEnv, project_input: str) -> Optional[dict]:
    """
    Find a project by numeric ID or by full name (TeamPath\\ProjectName,
    case-insensitive). Falls back to matching by short name alone when no
    full-path match is found.
    """
    if project_input.strip().isdigit():
        proj_id = int(project_input.strip())
        rows = env.odata_get_all(
            f"{ODATA_BASE}/Projects?$filter=Id eq {proj_id}"
            f"&$select=Id,Name,IsPublic,OwningTeamId,LastScanId"
        )
        if not rows:
            return None
        _attach_full_names(rows, _get_team_map(env))
        return rows[0]

    team_map = _get_team_map(env)
    rows = env.odata_get_all(
        f"{ODATA_BASE}/Projects?$select=Id,Name,IsPublic,OwningTeamId,LastScanId"
    )
    _attach_full_names(rows, team_map)

    name_lc = project_input.strip().lower()
    # Prefer full-path match (e.g. "CxServer\Test-Project"), fall back to short name
    matched = [p for p in rows if p["_FullName"].lower() == name_lc]
    if not matched:
        matched = [p for p in rows if (p.get("Name") or "").lower() == name_lc]

    if not matched:
        return None
    if len(matched) > 1:
        print(f"  WARNING: {len(matched)} projects matched '{project_input}', using first: "
              f"[{matched[0]['Id']}] {matched[0]['_FullName']}", file=sys.stderr)
    return matched[0]


def get_latest_scan(env: SastEnv, project_id: int) -> Optional[int]:
    """Return the latest finished scan ID for a project via REST."""
    scans = env.rest_get(f"{REST_BASE}/sast/scans?projectId={project_id}&scanStatus=Finished&last=1")
    if not scans:
        return None
    entry = scans[0] if isinstance(scans, list) else scans
    return entry.get("id")


def get_results_soap(env: SastEnv, scan_id: int) -> list[dict]:
    """Fetch all scan results via SOAP GetResultsForScan."""
    response = env.soap.service.GetResultsForScan(sessionID="0", scanId=scan_id)
    if not response.IsSuccesfull:
        raise ValueError(f"GetResultsForScan failed: {response.ErrorMessage}")
    if not response.Results or not response.Results.CxWSSingleResultData:
        return []
    return [
        {
            "QueryId":       item.QueryId,
            "PathId":        item.PathId,
            "SourceFolder":  item.SourceFolder or "",
            "SourceFile":    item.SourceFile   or "",
            "SourceLine":    item.SourceLine,
            "SourceObject":  item.SourceObject or "",
            "DestFolder":    item.DestFolder   or "",
            "DestFile":      item.DestFile     or "",
            "DestLine":      item.DestLine,
            "DestObject":    item.DestObject   or "",
            "NumberOfNodes": item.NumberOfNodes,
            "Comment":       item.Comment      or "",
            "State":         item.State,
            "Severity":      item.Severity,
            "AssignedUser":  item.AssignedUser  or "",
            "ResultStatus":  item.ResultStatus  or "",
        }
        for item in response.Results.CxWSSingleResultData
    ]


def get_similarity_map(env: SastEnv, scan_id: int) -> dict[int, str]:
    """Return {PathId: SimilarityId} for a scan via OData."""
    rows = env.odata_get_all(
        f"{ODATA_BASE}/Scans({scan_id})/Results?$select=PathId,SimilarityId"
    )
    return {r["PathId"]: str(r.get("SimilarityId") or "") for r in rows}


def get_query_collection(env: SastEnv) -> dict[int, dict]:
    """Return {QueryId: {Name, LanguageName, PackageName, PackageType, OwningTeam, ProjectId}}."""
    response = env.soap.service.GetQueryCollection(sessionId="0")
    if not response.IsSuccesfull:
        raise ValueError(f"GetQueryCollection failed: {response.ErrorMessage}")
    qmap: dict[int, dict] = {}
    if not response.QueryGroups:
        return qmap
    for group in response.QueryGroups.CxWSQueryGroup:
        if not group.Queries:
            continue
        for query in group.Queries.CxWSQuery:
            qmap[query.QueryId] = {
                "Name":         query.Name        or "",
                "LanguageName": group.LanguageName or "",
                "PackageName":  group.Name         or "",
                "PackageType":  group.PackageType  or "",
                "OwningTeam":   group.OwningTeam,
                "ProjectId":    group.ProjectId,
            }
    return qmap


def load_mapping(mapping_file: str) -> dict[tuple, str]:
    """Load mapping.json → {(language, group, queryName): targetQueryId str}."""
    with open(mapping_file, encoding="utf-8") as f:
        data = json.load(f)
    index = {}
    for entry in data.get("mappings", []):
        key = (
            (entry.get("language")   or "").strip(),
            (entry.get("group")      or "").strip(),
            (entry.get("queryName")  or "").strip(),
        )
        if all(key):
            index[key] = str(entry["targetQueryId"])
    return index


# ---------------------------------------------------------------------------
# SimilarityCalculator.exe (Windows only, optional)
# ---------------------------------------------------------------------------

def run_similarity_calculator(
    exe_path: str,
    source_path: str, source_name: str, source_line: str,
    dest_path: str,   dest_name: str,   dest_line: str,
    target_query_id: str, sim_version: str = "0",
) -> Optional[str]:
    """
    Call SimilarityCalculator.exe to compute a new similarity ID.

    Windows only. Requires the source and destination files to exist locally.
    Column and method line default to "0" as they are not available from
    SOAP results alone.

    Returns the computed similarity ID string, or None on failure.
    """
    try:
        result = subprocess.run(
            [
                exe_path,
                source_path, source_name, source_line, "0", "0",   # file, name, line, col, methodline
                dest_path,   dest_name,   dest_line,   "0", "0",   # file, name, line, col, methodline
                target_query_id,
                sim_version,
            ],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip() or None
        print(f"  SimilarityCalculator returned exit {result.returncode}: {result.stderr.strip()}", file=sys.stderr)
    except FileNotFoundError:
        print(f"  WARNING: SimilarityCalculator.exe not found at: {exe_path}", file=sys.stderr)
    except Exception as e:
        print(f"  WARNING: SimilarityCalculator failed: {e}", file=sys.stderr)
    return None


# ---------------------------------------------------------------------------
# Comment and triage history helpers
# ---------------------------------------------------------------------------

def _parse_comments(raw: str) -> List[str]:
    """Split a CxSAST ÿ-delimited comment history string into individual entries."""
    if not raw:
        return []
    comments: List[str] = []
    current = ""
    for part in raw.split("ÿ"):
        if not part.strip():
            continue
        if not current:
            current = part.rstrip()
        elif part.startswith(" - "):
            current = current + "ÿ" + part.rstrip()
        else:
            comments.append(current)
            current = part.rstrip()
    if current:
        comments.append(current.rstrip())
    return comments


def get_path_comments(env: SastEnv, scan_id: int, path_id: int) -> List[str]:
    """Return all individual comments for a result via SOAP GetPathCommentsHistory."""
    try:
        resp = env.soap.service.GetPathCommentsHistory(
            sessionId="0", scanId=scan_id, pathId=path_id, labelType="Remark"
        )
        if not resp.IsSuccesfull or not resp.Path or not resp.Path.Comment:
            return []
        return list(reversed(_parse_comments(resp.Path.Comment)))
    except Exception as e:
        print(f"  WARNING: GetPathCommentsHistory failed for PathId={path_id}: {e}", file=sys.stderr)
        return []


def _build_missing_comment(src_comments: List[str], tgt_comments: List[str]) -> Optional[str]:
    """
    Return a consolidated comment string containing source comments absent from the
    target, or None if nothing is missing. Follows the synchronizer's format.
    """
    missing = [
        sc for sc in src_comments
        if not any(tc.rstrip().endswith(sc.rstrip()) for tc in tgt_comments)
    ]
    if not missing:
        return None
    if len(missing) == 1:
        return missing[0]
    body = "Migrated comment(s)"
    for m in missing:
        body += "ÿ - " + m.rstrip().replace("[", "(", 1).replace("]", ")", 1)
    return body


def get_triage_history_map(env: SastEnv, scan_id: int) -> Dict[int, List[dict]]:
    """
    Return {PathId: [history entries sorted by date]} for all results in a scan
    via OData ResultTriageHistories expand. Returns empty dict if unavailable.
    """
    try:
        rows = env.odata_get_all(
            f"{ODATA_BASE}/Scans({scan_id})/Results"
            f"?$select=PathId&$expand=ResultTriageHistories"
        )
    except Exception as e:
        print(f"  WARNING: ResultTriageHistories unavailable — will apply final state only: {e}",
              file=sys.stderr)
        return {}
    hist: Dict[int, List[dict]] = {}
    for row in rows:
        pid = row.get("PathId")
        entries = row.get("ResultTriageHistories") or []
        if pid is not None and entries:
            hist[pid] = sorted(
                entries,
                key=lambda x: x.get("UpdateDate") or x.get("Date") or ""
            )
    return hist


def _write_source_triage_snapshot(project_id: int, scan_id: int, triaged: List[dict]) -> str:
    """
    Persist source triage data (state, severity, comment, assignee) for a
    project's scan to a temp JSON file, keyed by source PathId.

    Caching this locally lets the post-upload validation step compare
    against the source values without re-querying the source environment.
    """
    fd, path = tempfile.mkstemp(prefix=f"triage_src_{project_id}_{scan_id}_", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(
            {
                str(r["PathId"]): {
                    "State": r["State"],
                    "Severity": r["Severity"],
                    "Comment": r["Comment"],
                    "AssignedUser": r["AssignedUser"],
                }
                for r in triaged
            },
            f,
        )
    return path


def _load_source_triage_snapshot(path: str) -> Dict[str, dict]:
    """Load a temp JSON file previously written by _write_source_triage_snapshot."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Result matching
# ---------------------------------------------------------------------------

def match_result(orig: dict, candidates: List[dict]) -> Optional[dict]:
    """
    Match a source result to one target result using the path node approach from
    the synchronizer: QueryId (already pre-filtered) + SourceFile/Line/Object +
    DestFile/Line/Object + NumberOfNodes. Case-insensitive file comparisons.
    """
    for dest in candidates:
        if (
            str(dest["SourceFile"]).lower()   == str(orig["SourceFile"]).lower()   and
            dest["SourceLine"]                == orig["SourceLine"]                 and
            str(dest["SourceObject"]).lower() == str(orig["SourceObject"]).lower() and
            str(dest["DestFile"]).lower()     == str(orig["DestFile"]).lower()     and
            dest["DestLine"]                  == orig["DestLine"]                   and
            str(dest["DestObject"]).lower()   == str(orig["DestObject"]).lower()   and
            dest["NumberOfNodes"]             == orig["NumberOfNodes"]
        ):
            return dest
    return None


# ---------------------------------------------------------------------------
# Triage upload
# ---------------------------------------------------------------------------

def upload_label_calls(env: SastEnv, scan_id: int, label_calls: List[dict], dry_run: bool) -> None:
    """
    Apply triage changes via `PATCH /cxrestapi/sast/scans/{scanId}/results/{pathId}/labels`,
    one call per entry in `label_calls`, in order.

    This is the endpoint CxSAST actually applies state changes through; the
    older SOAP `UpdateSetOfResultState` call and the bulk `.../results` REST
    endpoint were both found to silently no-op state changes.

    `label_calls` entries carry a path's full historical sequence of changes
    in order (see process_project), so replaying them call-by-call recreates
    the source's triage timeline on the target. Each entry only includes the
    field(s) that actually changed at that step (plus `comment`, always
    present even if empty) — the target logs a distinct audit entry for
    every field present in the request, even when the value sent matches
    what's already there, so unchanged fields must be omitted rather than
    resent with their current value.
    """
    if not label_calls:
        print("  No triage changes to upload.")
        return
    if dry_run:
        print(f"  [DRY RUN] Would upload {len(label_calls)} label update(s) via "
              f"PATCH .../results/{{pathId}}/labels")
        return

    failures = 0
    for i, item in enumerate(label_calls, 1):
        path = f"{REST_BASE}/sast/scans/{scan_id}/results/{item['pathId']}/labels"
        payload = {k: v for k, v in item.items() if k != "pathId"}
        payload.setdefault("comment", "")
        try:
            status, body = env.rest_patch(path, payload)
        except Exception as e:
            print(f"  ERROR uploading label update {i}/{len(label_calls)} "
                  f"(PathId={item['pathId']}, request failed): {e}", file=sys.stderr)
            failures += 1
            continue

        if status >= 400:
            failures += 1
            print(f"  ERROR uploading label update {i}/{len(label_calls)}: HTTP {status} "
                  f"PathId={item['pathId']} payload={payload} response={body}", file=sys.stderr)
            continue

        print(f"  Uploaded {i}/{len(label_calls)} label update "
              f"PathId={item['pathId']} HTTP {status} payload={payload} response={body}")

    if failures:
        print(f"  WARNING: {failures}/{len(label_calls)} label update(s) failed", file=sys.stderr)


# ---------------------------------------------------------------------------
# Per-project migration
# ---------------------------------------------------------------------------

def process_project(
    project_input: str,
    source_env: SastEnv,
    target_env: SastEnv,
    src_queries: dict,
    tgt_queries: dict,
    tgt_query_by_key: Dict[tuple, List[int]],
    mapping: dict,
    sim_exe: Optional[str],
    args,
) -> Tuple[List[dict], Dict[str, int], bool, bool]:
    """
    Migrate triage data for a single project (find → match → upload).

    Returns (csv_rows, counts, ok, skipped). ok is False when the project or
    one of its scans could not be found, so the caller can report it as a
    failure rather than a project with zero triaged results. skipped is True
    when the target scan already has triage data, in which case the import
    is not attempted so existing target triages are never overwritten.
    """
    counts = {"matched": 0, "not_found": 0, "query_missing": 0, "error": 0}
    csv_rows: List[dict] = []

    # -----------------------------------------------------------------------
    # SOURCE
    # -----------------------------------------------------------------------
    print(f"\n=== SOURCE ({source_env.url}) ===")

    print(f"Finding project: {project_input!r}")
    src_project = get_project(source_env, project_input)
    if not src_project:
        print(f"ERROR: Project {project_input!r} not found in source.", file=sys.stderr)
        return csv_rows, counts, False, False
    print(f"  [{src_project['Id']}] {src_project.get('_FullName') or src_project['Name']}")

    src_scan_id = get_latest_scan(source_env, src_project["Id"])
    if not src_scan_id:
        print("ERROR: No finished scans in source project.", file=sys.stderr)
        return csv_rows, counts, False, False
    print(f"  Latest finished scan: {src_scan_id}")

    print("  Loading scan results (SOAP)...")
    all_src_results = get_results_soap(source_env, src_scan_id)
    triaged_src = [r for r in all_src_results if r["State"] > 0 or r["Comment"] or r["AssignedUser"]]
    print(f"  {len(all_src_results)} total, {len(triaged_src)} triaged")

    print("  Loading SimilarityIds (OData)...")
    src_sim_map = get_similarity_map(source_env, src_scan_id)
    print(f"  {len(src_sim_map)} similarity IDs")

    print("  Loading triage history (OData)...")
    src_triage_hist = get_triage_history_map(source_env, src_scan_id)
    if src_triage_hist:
        total_hist = sum(len(v) for v in src_triage_hist.values())
        print(f"  {total_hist} history entries across {len(src_triage_hist)} results")

    print("  Caching source triage snapshot (temp file)...")
    triage_temp_path = _write_source_triage_snapshot(src_project["Id"], src_scan_id, triaged_src)
    validation_map: Dict[int, int] = {}  # target PathId -> source PathId

    try:
        # -----------------------------------------------------------------------
        # TARGET
        # -----------------------------------------------------------------------
        print(f"\n=== TARGET ({target_env.url}) ===")

        src_full_name = src_project.get("_FullName") or src_project["Name"]
        print(f"Finding project by name: {src_full_name!r}")
        tgt_project = get_project(target_env, src_full_name)
        if not tgt_project:
            print(f"ERROR: Project {src_full_name!r} not found in target.", file=sys.stderr)
            return csv_rows, counts, False, False
        print(f"  [{tgt_project['Id']}] {tgt_project.get('_FullName') or tgt_project['Name']}")

        tgt_scan_id = get_latest_scan(target_env, tgt_project["Id"])
        if not tgt_scan_id:
            print("ERROR: No finished scans in target project.", file=sys.stderr)
            return csv_rows, counts, False, False
        print(f"  Latest finished scan: {tgt_scan_id}")

        print("  Loading scan results (SOAP)...")
        all_tgt_results = get_results_soap(target_env, tgt_scan_id)
        print(f"  {len(all_tgt_results)} total results")

        if any(r["State"] > 0 or r["Comment"] or r["AssignedUser"] for r in all_tgt_results):
            print(f"  SKIPPED: target scan {tgt_scan_id} already has triage data — "
                  f"import skipped to avoid overwriting existing triages.")
            csv_rows.append({
                "status": "SKIPPED", "source_project_id": src_project["Id"],
                "source_scan_id": src_scan_id, "target_project_id": tgt_project["Id"],
                "target_scan_id": tgt_scan_id, "query_name": "", "language": "", "group": "",
                "source_path_id": "", "target_path_id": "", "source_similarity_id": "",
                "target_similarity_id": "", "computed_similarity_id": "",
                "source_state": "", "source_severity": "", "source_comment": "",
                "detail": "Target scan already has triage data; import skipped",
            })
            return csv_rows, counts, True, True

        print("  Loading SimilarityIds (OData)...")
        tgt_sim_map = get_similarity_map(target_env, tgt_scan_id)
        print(f"  {len(tgt_sim_map)} similarity IDs")

        # Index target results by QueryId for fast lookup
        tgt_by_query: Dict[int, list[dict]] = {}
        for r in all_tgt_results:
            tgt_by_query.setdefault(r["QueryId"], []).append(r)

        # -----------------------------------------------------------------------
        # MATCH & COLLECT TRIAGES
        # -----------------------------------------------------------------------
        print(f"\n=== Matching {len(triaged_src)} triaged source results ===")

        label_calls: List[dict] = []

        for orig in triaged_src:
            src_qid   = orig["QueryId"]
            src_qinfo = src_queries.get(src_qid)
            src_sim   = src_sim_map.get(orig["PathId"], "")

            row_base = {
                "source_project_id": src_project["Id"],
                "source_scan_id":    src_scan_id,
                "target_project_id": tgt_project["Id"],
                "target_scan_id":    tgt_scan_id,
                "source_path_id":    orig["PathId"],
                "source_similarity_id": src_sim,
                "source_state":    orig["State"],
                "source_severity": orig["Severity"],
                "source_comment":  orig["Comment"],
            }

            if not src_qinfo:
                counts["error"] += 1
                csv_rows.append({**row_base, "status": "ERROR", "query_name": "", "language": "",
                                 "group": "", "target_path_id": "", "target_similarity_id": "",
                                 "computed_similarity_id": "",
                                 "detail": f"Source QueryId {src_qid} not in query collection"})
                continue

            lang  = src_qinfo["LanguageName"]
            group = src_qinfo["PackageName"]
            name  = src_qinfo["Name"]
            mk    = (lang.strip(), group.strip(), name.strip())

            # Resolve candidate target QueryIds: mapping.json's choice first (if any),
            # then every other target query sharing this (language, group, name) — the
            # same name can exist more than once in the target (e.g. a custom query
            # overridden per-team/per-project), each copy with its own QueryId, and
            # mapping.json only ever recorded one of them. Try each in turn and use
            # whichever one actually has a matching result in this scan.
            mapped_qid_str = mapping.get(mk)
            same_name_qids = tgt_query_by_key.get(mk, [])
            candidate_qids: List[int] = []
            if mapped_qid_str:
                candidate_qids.append(int(mapped_qid_str))
            for qid in same_name_qids:
                if qid not in candidate_qids:
                    candidate_qids.append(qid)

            if not candidate_qids:
                counts["query_missing"] += 1
                csv_rows.append({**row_base, "status": "NO_QUERY", "query_name": name,
                                 "language": lang, "group": group, "target_path_id": "",
                                 "target_similarity_id": "", "computed_similarity_id": "",
                                 "detail": "Query not in mapping.json and not found in target"})
                continue

            # Optionally compute new SimilarityId via SimilarityCalculator.exe
            computed_sim = ""
            if sim_exe:
                src_path = os.path.join(orig["SourceFolder"], orig["SourceFile"]) if orig["SourceFolder"] else orig["SourceFile"]
                dst_path = os.path.join(orig["DestFolder"],   orig["DestFile"])   if orig["DestFolder"]   else orig["DestFile"]
                computed_sim = run_similarity_calculator(
                    sim_exe,
                    src_path, orig["SourceObject"], str(orig["SourceLine"]),
                    dst_path, orig["DestObject"],   str(orig["DestLine"]),
                    str(candidate_qids[0]), args.sim_version,
                ) or ""

            # Match by path nodes, trying each candidate QueryId in order
            dest = None
            tgt_qid = candidate_qids[0]
            tried = []
            for qid in candidate_qids:
                qid_candidates = tgt_by_query.get(qid, [])
                tried.append((qid, len(qid_candidates)))
                m = match_result(orig, qid_candidates)
                if m is not None:
                    dest = m
                    tgt_qid = qid
                    break

            if dest is None:
                counts["not_found"] += 1
                tried_str = ", ".join(f"QueryId={q} ({n} result(s))" for q, n in tried)
                detail = f"No matching result found in target scan; tried {tried_str}"
                csv_rows.append({**row_base, "status": "NOT_FOUND", "query_name": name,
                                 "language": lang, "group": group, "target_path_id": "",
                                 "target_similarity_id": "", "computed_similarity_id": computed_sim,
                                 "detail": detail})
                print(f"  NOT FOUND  [{src_qid}] {lang}/{name} tried={tried_str} "
                      f"src={orig['SourceFile']}:{orig['SourceLine']}:{orig['SourceObject']} "
                      f"dst={orig['DestFile']}:{orig['DestLine']}:{orig['DestObject']} nodes={orig['NumberOfNodes']}")
                for qid, _ in tried:
                    sample = tgt_by_query.get(qid, [])
                    if sample:
                        c = sample[0]
                        print(f"    sample target candidate (QueryId={qid}): "
                              f"src={c['SourceFile']}:{c['SourceLine']}:{c['SourceObject']} "
                              f"dst={c['DestFile']}:{c['DestLine']}:{c['DestObject']} nodes={c['NumberOfNodes']}")
                continue

            if len(candidate_qids) > 1 and tgt_qid != candidate_qids[0]:
                print(f"  NOTE: [{src_qid}] {lang}/{name} matched via fallback QueryId={tgt_qid} "
                      f"(mapping.json/first candidate {candidate_qids[0]} had no match)")

            counts["matched"] += 1
            validation_map[dest["PathId"]] = orig["PathId"]
            dest_sim = tgt_sim_map.get(dest["PathId"], "")
            base_label = {"pathId": dest["PathId"]}

            # Comment: fetch full history and build one consolidated string containing
            # any source entries missing from the target (existing proven mechanism).
            # Attached to the LAST label call below rather than per history step, since
            # we can't reliably tell which ResultTriageHistories entry (if any) the
            # comment text actually belongs to.
            src_cmts: List[str] = []
            missing_cmt = ""
            if orig["Comment"]:
                src_cmts = get_path_comments(source_env, src_scan_id, orig["PathId"])
                tgt_cmts = (get_path_comments(target_env, tgt_scan_id, dest["PathId"])
                            if dest["Comment"] else [])
                missing_cmt = _build_missing_comment(src_cmts, tgt_cmts) or ""

            # State/severity/assignee: replay every historical change in order via
            # PATCH .../results/{pathId}/labels (one call per step) if OData history
            # is available; otherwise fall back to applying the final values only.
            # Each call includes ONLY the field(s) that actually changed at that step —
            # the target logs a distinct audit entry for every field present in the
            # request, even when its value matches what's already there, so sending
            # severity/userAssignment unconditionally produces spurious "Changed
            # severity"/"Assigned to None" entries.
            result_calls: List[dict] = []
            path_history = src_triage_hist.get(orig["PathId"], [])
            if path_history:
                prev_state = dest["State"]
                prev_sev   = dest["Severity"]
                prev_user  = dest["AssignedUser"] or ""
                for entry in path_history:
                    e_state = entry.get("State")
                    e_sev   = entry.get("Severity")
                    e_user  = entry.get("AssignedToUser") or entry.get("AssignedUser") or ""
                    call = {}
                    if e_state is not None and e_state != prev_state:
                        prev_state = e_state
                        call["state"] = prev_state
                    if e_sev is not None and e_sev != prev_sev:
                        prev_sev = e_sev
                        call["severity"] = prev_sev
                    if e_user and e_user != prev_user:
                        prev_user = e_user
                        call["userAssignment"] = prev_user
                    if call:
                        result_calls.append({**base_label, **call, "comment": ""})
            else:
                # Fallback: apply final values only
                call = {}
                if orig["State"] > 0 and orig["State"] != dest["State"]:
                    call["state"] = orig["State"]
                if orig["Severity"] != dest["Severity"]:
                    call["severity"] = orig["Severity"]
                if orig["AssignedUser"] and orig["AssignedUser"] != dest["AssignedUser"]:
                    call["userAssignment"] = orig["AssignedUser"]
                if call:
                    result_calls.append({**base_label, **call, "comment": ""})

            # Attach the consolidated comment to the last call so it's always sent,
            # adding a comment-only call (no state/severity/assignee) if nothing else changed.
            if missing_cmt:
                if result_calls:
                    result_calls[-1]["comment"] = missing_cmt
                else:
                    result_calls.append({**base_label, "comment": missing_cmt})

            label_calls.extend(result_calls)

            full_comment = "ÿ".join(src_cmts) if src_cmts else orig["Comment"]
            csv_rows.append({**row_base, "status": "MATCHED", "query_name": name,
                             "language": lang, "group": group,
                             "source_comment":        full_comment,
                             "target_path_id":        dest["PathId"],
                             "target_similarity_id":  dest_sim,
                             "computed_similarity_id": computed_sim,
                             "detail": ""})

        print(f"  Matched:       {counts['matched']}")
        print(f"  Not found:     {counts['not_found']}")
        print(f"  Query missing: {counts['query_missing']}")
        print(f"  Errors:        {counts['error']}")

        # -----------------------------------------------------------------------
        # UPLOAD
        # -----------------------------------------------------------------------
        print(f"\n=== Uploading triages for project [{src_project['Id']}] ===")
        upload_label_calls(target_env, tgt_scan_id, label_calls, args.dry_run)

        if not args.dry_run and validation_map:
            print(f"\n=== Validating {len(validation_map)} uploaded triage(s) against source snapshot ===")
            src_snapshot = _load_source_triage_snapshot(triage_temp_path)
            fresh_tgt_results = get_results_soap(target_env, tgt_scan_id)
            fresh_by_path = {r["PathId"]: r for r in fresh_tgt_results}
            mismatches = 0
            for tgt_path_id, src_path_id in validation_map.items():
                actual = fresh_by_path.get(tgt_path_id)
                src_rec = src_snapshot.get(str(src_path_id), {})
                if actual is None:
                    mismatches += 1
                    print(f"  MISMATCH PathId={tgt_path_id}: result missing from target after upload")
                    continue
                problems = []
                if actual["State"] != src_rec.get("State"):
                    problems.append(f"state {actual['State']} != {src_rec.get('State')}")
                if actual["Severity"] != src_rec.get("Severity"):
                    problems.append(f"severity {actual['Severity']} != {src_rec.get('Severity')}")
                if src_rec.get("AssignedUser") and actual["AssignedUser"] != src_rec.get("AssignedUser"):
                    problems.append(f"assignee {actual['AssignedUser']!r} != {src_rec.get('AssignedUser')!r}")
                if src_rec.get("Comment") and not actual["Comment"]:
                    problems.append("comment missing")
                if problems:
                    mismatches += 1
                    print(f"  MISMATCH PathId={tgt_path_id}: {', '.join(problems)}")
            print(f"  Validated {len(validation_map) - mismatches}/{len(validation_map)} triages applied correctly")

        return csv_rows, counts, True, False
    finally:
        os.remove(triage_temp_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Migrate SAST triage data from source project to target project."
    )
    project_group = parser.add_mutually_exclusive_group(required=True)
    project_group.add_argument("--project", default=None,
                        help="Source project name (exact, case-insensitive) or numeric project ID")
    project_group.add_argument("--project-list", default=None,
                        help="Comma-separated list of source project names or numeric IDs to migrate")
    parser.add_argument("--mapping",  default=os.getenv("MAPPING_FILE", "mapping.json"),
                        help="Path to query mapping JSON (default: mapping.json)")
    parser.add_argument("--output",   default="triage_migration.csv",
                        help="Output CSV file (default: triage_migration.csv)")
    parser.add_argument("--similarity-calculator", default=None, metavar="EXE",
                        help="Path to SimilarityCalculator.exe (Windows only, optional). "
                             "Computes target similarity IDs from source path node data + "
                             "mapped target query IDs.")
    parser.add_argument("--sim-version", default="0", choices=["0", "1", "2"],
                        help="SimilarityCalculator version argument (default: 0)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Fetch and match everything but skip uploading triages")
    args = parser.parse_args()

    def require_env(var: str, label: str) -> str:
        val = os.getenv(var, "").strip()
        if not val:
            print(f"ERROR: {label} is not set ({var})", file=sys.stderr)
            sys.exit(1)
        return val

    source_url  = require_env("SOURCE_URL",      "Source URL")
    source_user = require_env("SOURCE_USERNAME",  "Source username")
    source_pass = require_env("SOURCE_PASSWORD",  "Source password")
    target_url  = require_env("TARGET_URL",       "Target URL")
    target_user = require_env("TARGET_USERNAME",  "Target username")
    target_pass = require_env("TARGET_PASSWORD",  "Target password")
    verify_ssl  = os.getenv("VERIFY_SSL", "true").strip().lower() != "false"

    if not verify_ssl:
        disable_warnings(InsecureRequestWarning)
        print("WARNING: SSL verification disabled", file=sys.stderr)

    # Validate mapping file
    if not os.path.isfile(args.mapping):
        print(f"ERROR: Mapping file not found: {args.mapping}. Run generate_mapping.py first.", file=sys.stderr)
        sys.exit(1)
    mapping = load_mapping(args.mapping)
    print(f"Loaded {len(mapping)} query mappings from {args.mapping}")

    # Validate SimilarityCalculator.exe
    sim_exe = args.similarity_calculator
    if sim_exe:
        if platform.system() != "Windows":
            print("WARNING: SimilarityCalculator.exe is Windows-only — skipping on this platform.", file=sys.stderr)
            sim_exe = None
        elif not os.path.isfile(sim_exe):
            print(f"WARNING: SimilarityCalculator.exe not found: {sim_exe}", file=sys.stderr)
            sim_exe = None

    source_env = SastEnv(source_url, source_user, source_pass, verify_ssl)
    target_env = SastEnv(target_url, target_user, target_pass, verify_ssl)

    if args.project_list:
        projects = [p.strip() for p in args.project_list.split(",") if p.strip()]
        if not projects:
            print("ERROR: --project-list did not contain any project names/IDs.", file=sys.stderr)
            sys.exit(1)
    else:
        projects = [args.project]

    # Query collections are environment-wide, not project-specific, so fetch
    # them once and reuse them across every project in the list.
    print("Loading query collection (source)...")
    src_queries = get_query_collection(source_env)
    print(f"  {len(src_queries)} queries")

    print("Loading query collection (target)...")
    tgt_queries = get_query_collection(target_env)
    print(f"  {len(tgt_queries)} queries")

    # Map each (language, group, name) key to ALL matching target QueryIds, not just
    # one — the same query name can exist multiple times in the target's query
    # collection (e.g. a custom query overridden per-team/per-project), each copy
    # with its own QueryId. Picking the wrong one silently yields zero scan results
    # for that query even though the name "matches".
    tgt_query_by_key: Dict[tuple, List[int]] = {}
    for qid, qi in tgt_queries.items():
        key = (qi["LanguageName"].strip(), qi["PackageName"].strip(), qi["Name"].strip())
        tgt_query_by_key.setdefault(key, []).append(qid)

    for key, qids in tgt_query_by_key.items():
        if len(qids) > 1:
            details = ", ".join(
                f"QueryId={q} OwningTeam={tgt_queries[q].get('OwningTeam')} "
                f"ProjectId={tgt_queries[q].get('ProjectId')}"
                for q in qids
            )
            print(f"  WARNING: target has {len(qids)} queries named {key!r}: {details}",
                  file=sys.stderr)

    all_csv_rows: List[dict] = []
    total_counts = {"matched": 0, "not_found": 0, "query_missing": 0, "error": 0}
    failed_projects: List[str] = []
    skipped_projects: List[str] = []

    for i, project_input in enumerate(projects, 1):
        if len(projects) > 1:
            print(f"\n{'#' * 70}\n# Project {i}/{len(projects)}: {project_input}\n{'#' * 70}")

        csv_rows, counts, ok, skipped = process_project(
            project_input, source_env, target_env,
            src_queries, tgt_queries, tgt_query_by_key,
            mapping, sim_exe, args,
        )
        if not ok:
            failed_projects.append(project_input)
        elif skipped:
            skipped_projects.append(project_input)
        all_csv_rows.extend(csv_rows)
        for k in total_counts:
            total_counts[k] += counts[k]

    # -----------------------------------------------------------------------
    # CSV
    # -----------------------------------------------------------------------
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_csv_rows)

    print(f"\nCSV written to: {args.output}")
    print(f"  Matched:       {total_counts['matched']}")
    print(f"  Not found:     {total_counts['not_found']}")
    print(f"  Query missing: {total_counts['query_missing']}")
    print(f"  Errors:        {total_counts['error']}")
    if skipped_projects:
        print(f"  Skipped projects (target already has triage data): {', '.join(skipped_projects)}")
    if failed_projects:
        print(f"  Failed projects (not found / no scans): {', '.join(failed_projects)}", file=sys.stderr)

    print("\nDone.")
    if failed_projects:
        sys.exit(1)


if __name__ == "__main__":
    main()
