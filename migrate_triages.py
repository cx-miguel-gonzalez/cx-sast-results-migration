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
from typing import Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv
from requests import Session
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from zeep import Client, Settings, xsd
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

COMMIT_CHUNKS = 100

LABEL_COMMENT  = 1
LABEL_SEVERITY = 2
LABEL_STATE    = 3
LABEL_ASSIGNEE = 4

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

def _upload_batch(soap: Client, triages: list[dict], label: str) -> int:
    """Upload a list of triage records in chunks. Returns count of failed items."""
    if not triages:
        return 0
    factory = soap.type_factory("ns0")
    failures = 0
    for i in range(0, len(triages), COMMIT_CHUNKS):
        chunk = triages[i : i + COMMIT_CHUNKS]
        try:
            triage_data = factory.ArrayOfResultStateData([
                factory.ResultStateData(
                    scanId=item["scanId"],
                    PathId=item["PathId"],
                    projectId=item["projectId"],
                    Remarks=item["Remarks"] if item["Remarks"] else xsd.SkipValue,
                    ResultLabelType=item["ResultLabelType"],
                    data=item["data"],
                ) for item in chunk
            ])
            soap.service.UpdateSetOfResultState(sessionID="0", resultsStates=triage_data)
            print(f"  Uploaded {min(i + COMMIT_CHUNKS, len(triages))}/{len(triages)} {label}")
        except Exception as e:
            print(f"  ERROR uploading {label} chunk: {e}", file=sys.stderr)
            failures += len(chunk)
    return failures


def upload_all_triages(
    env: SastEnv,
    comments: list[dict],
    assignees: list[dict],
    severities: list[dict],
    states: list[dict],
    dry_run: bool,
) -> None:
    """Upload triages in the required order: comments → assignees → severities → states."""
    total = len(comments) + len(assignees) + len(severities) + len(states)
    if total == 0:
        print("  No triage changes to upload.")
        return
    if dry_run:
        print(f"  [DRY RUN] Would upload: {len(comments)} comments, {len(assignees)} assignees, "
              f"{len(severities)} severities, {len(states)} states")
        return

    soap = env.soap
    factory = soap.type_factory("ns0")
    failures = 0

    # Comments must be sent one at a time
    for i, item in enumerate(comments, 1):
        try:
            triage_data = factory.ArrayOfResultStateData([
                factory.ResultStateData(
                    scanId=item["scanId"],
                    PathId=item["PathId"],
                    projectId=item["projectId"],
                    Remarks=item["Remarks"],
                    ResultLabelType=item["ResultLabelType"],
                    data=item["data"],
                )
            ])
            soap.service.UpdateSetOfResultState(sessionID="0", resultsStates=triage_data)
        except Exception as e:
            print(f"  ERROR uploading comment {i}/{len(comments)} (PathId={item['PathId']}): {e}", file=sys.stderr)
            failures += 1
    if comments:
        print(f"  Uploaded {len(comments) - failures}/{len(comments)} comments")

    failures += _upload_batch(soap, assignees,  "assignees")
    failures += _upload_batch(soap, severities, "severities")
    failures += _upload_batch(soap, states,     "states")

    if failures:
        print(f"  WARNING: {failures} triage upload(s) failed", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Migrate SAST triage data from source project to target project."
    )
    parser.add_argument("--project",  required=True,
                        help="Source project name (exact, case-insensitive) or numeric project ID")
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

    # -----------------------------------------------------------------------
    # SOURCE
    # -----------------------------------------------------------------------
    print(f"\n=== SOURCE ({source_url}) ===")

    print(f"Finding project: {args.project!r}")
    src_project = get_project(source_env, args.project)
    if not src_project:
        print(f"ERROR: Project {args.project!r} not found in source.", file=sys.stderr)
        sys.exit(1)
    print(f"  [{src_project['Id']}] {src_project.get('_FullName') or src_project['Name']}")

    src_scan_id = get_latest_scan(source_env, src_project["Id"])
    if not src_scan_id:
        print("ERROR: No finished scans in source project.", file=sys.stderr)
        sys.exit(1)
    print(f"  Latest finished scan: {src_scan_id}")

    print("  Loading query collection...")
    src_queries = get_query_collection(source_env)
    print(f"  {len(src_queries)} queries")

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

    # -----------------------------------------------------------------------
    # TARGET
    # -----------------------------------------------------------------------
    print(f"\n=== TARGET ({target_url}) ===")

    src_full_name = src_project.get("_FullName") or src_project["Name"]
    print(f"Finding project by name: {src_full_name!r}")
    tgt_project = get_project(target_env, src_full_name)
    if not tgt_project:
        print(f"ERROR: Project {src_full_name!r} not found in target.", file=sys.stderr)
        sys.exit(1)
    print(f"  [{tgt_project['Id']}] {tgt_project.get('_FullName') or tgt_project['Name']}")

    tgt_scan_id = get_latest_scan(target_env, tgt_project["Id"])
    if not tgt_scan_id:
        print("ERROR: No finished scans in target project.", file=sys.stderr)
        sys.exit(1)
    print(f"  Latest finished scan: {tgt_scan_id}")

    print("  Loading query collection...")
    tgt_queries = get_query_collection(target_env)
    print(f"  {len(tgt_queries)} queries")

    print("  Loading scan results (SOAP)...")
    all_tgt_results = get_results_soap(target_env, tgt_scan_id)
    print(f"  {len(all_tgt_results)} total results")

    print("  Loading SimilarityIds (OData)...")
    tgt_sim_map = get_similarity_map(target_env, tgt_scan_id)
    print(f"  {len(tgt_sim_map)} similarity IDs")

    # Index target results by QueryId for fast lookup
    tgt_by_query: dict[int, list[dict]] = {}
    for r in all_tgt_results:
        tgt_by_query.setdefault(r["QueryId"], []).append(r)

    # Build target query index: (language, group, name) → QueryId
    tgt_query_by_key: dict[tuple, int] = {}
    for qid, qi in tgt_queries.items():
        key = (qi["LanguageName"].strip(), qi["PackageName"].strip(), qi["Name"].strip())
        tgt_query_by_key[key] = qid

    # -----------------------------------------------------------------------
    # MATCH & COLLECT TRIAGES
    # -----------------------------------------------------------------------
    print(f"\n=== Matching {len(triaged_src)} triaged source results ===")

    comments:   list[dict] = []
    assignees:  list[dict] = []
    severities: list[dict] = []
    states:     list[dict] = []
    csv_rows:   list[dict] = []

    counts = {"matched": 0, "not_found": 0, "query_missing": 0, "error": 0}

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

        # Resolve target QueryId: prefer mapping.json, fall back to direct name match
        tgt_qid_str = mapping.get(mk)
        if not tgt_qid_str:
            direct = tgt_query_by_key.get(mk)
            if direct:
                tgt_qid_str = str(direct)
            else:
                counts["query_missing"] += 1
                csv_rows.append({**row_base, "status": "NO_QUERY", "query_name": name,
                                 "language": lang, "group": group, "target_path_id": "",
                                 "target_similarity_id": "", "computed_similarity_id": "",
                                 "detail": "Query not in mapping.json and not found in target"})
                continue

        tgt_qid = int(tgt_qid_str)

        # Optionally compute new SimilarityId via SimilarityCalculator.exe
        computed_sim = ""
        if sim_exe:
            src_path = os.path.join(orig["SourceFolder"], orig["SourceFile"]) if orig["SourceFolder"] else orig["SourceFile"]
            dst_path = os.path.join(orig["DestFolder"],   orig["DestFile"])   if orig["DestFolder"]   else orig["DestFile"]
            computed_sim = run_similarity_calculator(
                sim_exe,
                src_path, orig["SourceObject"], str(orig["SourceLine"]),
                dst_path, orig["DestObject"],   str(orig["DestLine"]),
                tgt_qid_str, args.sim_version,
            ) or ""

        # Match by path nodes
        dest = match_result(orig, tgt_by_query.get(tgt_qid, []))
        if dest is None:
            counts["not_found"] += 1
            csv_rows.append({**row_base, "status": "NOT_FOUND", "query_name": name,
                             "language": lang, "group": group, "target_path_id": "",
                             "target_similarity_id": "", "computed_similarity_id": computed_sim,
                             "detail": "No matching result found in target scan"})
            print(f"  NOT FOUND  [{src_qid}→{tgt_qid}] {lang}/{name} "
                  f"src={orig['SourceFile']}:{orig['SourceLine']} "
                  f"dst={orig['DestFile']}:{orig['DestLine']}")
            continue

        counts["matched"] += 1
        dest_sim = tgt_sim_map.get(dest["PathId"], "")
        base_triage = {
            "projectId": tgt_project["Id"],
            "scanId":    tgt_scan_id,
            "PathId":    dest["PathId"],
        }

        # Comments: fetch full history and add any entries missing from target
        src_cmts: List[str] = []
        if orig["Comment"]:
            src_cmts = get_path_comments(source_env, src_scan_id, orig["PathId"])
            tgt_cmts = (get_path_comments(target_env, tgt_scan_id, dest["PathId"])
                        if dest["Comment"] else [])
            missing_cmt = _build_missing_comment(src_cmts, tgt_cmts)
            if missing_cmt:
                comments.append({**base_triage, "ResultLabelType": LABEL_COMMENT,
                                 "Remarks": missing_cmt, "data": missing_cmt})

        # State/severity/assignee: replay every historical change in order if OData
        # history is available; otherwise fall back to applying the final state only.
        path_history = src_triage_hist.get(orig["PathId"], [])
        if path_history:
            prev_state = 0
            prev_sev   = -1
            prev_user  = ""
            for entry in path_history:
                e_state = entry.get("State") or 0
                e_sev   = entry.get("Severity") if entry.get("Severity") is not None else -1
                e_user  = entry.get("AssignedToUser") or entry.get("AssignedUser") or ""
                if e_state and e_state != prev_state:
                    states.append({**base_triage, "ResultLabelType": LABEL_STATE,
                                   "Remarks": None, "data": e_state})
                    prev_state = e_state
                if e_sev >= 0 and e_sev != prev_sev:
                    severities.append({**base_triage, "ResultLabelType": LABEL_SEVERITY,
                                       "Remarks": None, "data": e_sev})
                    prev_sev = e_sev
                if e_user and e_user != prev_user:
                    assignees.append({**base_triage, "ResultLabelType": LABEL_ASSIGNEE,
                                      "Remarks": None, "data": e_user})
                    prev_user = e_user
        else:
            # Fallback: apply final state only
            if orig["State"] > 0 and orig["State"] != dest["State"]:
                states.append({**base_triage, "ResultLabelType": LABEL_STATE,
                               "Remarks": None, "data": orig["State"]})
            if orig["Severity"] != dest["Severity"]:
                severities.append({**base_triage, "ResultLabelType": LABEL_SEVERITY,
                                   "Remarks": None, "data": orig["Severity"]})
            if orig["AssignedUser"] and orig["AssignedUser"] != dest["AssignedUser"]:
                assignees.append({**base_triage, "ResultLabelType": LABEL_ASSIGNEE,
                                  "Remarks": None, "data": orig["AssignedUser"]})

        full_comment = "ÿ".join(src_cmts) if src_cmts else orig["Comment"]
        csv_rows.append({**row_base, "status": "MATCHED", "query_name": name,
                         "language": lang, "group": group,
                         "source_comment":        full_comment,
                         "target_path_id":        dest["PathId"],
                         "target_similarity_id":  dest_sim,
                         "computed_similarity_id": computed_sim,
                         "detail": ""})

    # -----------------------------------------------------------------------
    # CSV
    # -----------------------------------------------------------------------
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(csv_rows)

    print(f"\nCSV written to: {args.output}")
    print(f"  Matched:       {counts['matched']}")
    print(f"  Not found:     {counts['not_found']}")
    print(f"  Query missing: {counts['query_missing']}")
    print(f"  Errors:        {counts['error']}")

    # -----------------------------------------------------------------------
    # UPLOAD
    # -----------------------------------------------------------------------
    print(f"\n=== Uploading triages ===")
    upload_all_triages(target_env, comments, assignees, severities, states, args.dry_run)

    print("\nDone.")


if __name__ == "__main__":
    main()
