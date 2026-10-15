#!/usr/bin/env python3
"""
Generate a query ID mapping file between two Checkmarx SAST environments.

Queries are fetched via the SOAP GetQueryCollection operation and matched by
(LanguageName, GroupName, QueryName). The output JSON maps sourceQueryId ->
targetQueryId for all queries that exist in both environments.

Usage:
    cp .env.example .env   # fill in credentials
    python3 -m pip install -r requirements.txt
    python3 generate_mapping.py [--output mapping.json]
"""

import argparse
import json
import os
import sys

import requests
from dotenv import load_dotenv
from requests import Session
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from zeep import Client, Settings
from zeep.transports import Transport

load_dotenv()

WSDL_PATH  = "/CxWebInterface/Portal/CxWebService.asmx?wsdl"
TOKEN_PATH = "/cxrestapi/auth/identity/connect/token"
SOAP_SCOPE  = "offline_access sast_api"
SOAP_CLIENT = "resource_owner_sast_client"
ODATA_SCOPE  = "access_control_api sast_api"
ODATA_CLIENT = "resource_owner_sast_client"
ODATA_BASE = "/Cxwebinterface/odata/v1"
REST_BASE  = "/cxrestapi"
CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"


def get_bearer_token(base_url: str, username: str, password: str, verify_ssl: bool,
                      scope: str = SOAP_SCOPE, client_id: str = SOAP_CLIENT) -> str:
    url = base_url.rstrip("/") + TOKEN_PATH
    payload = {
        "username": username,
        "password": password,
        "grant_type": "password",
        "scope": scope,
        "client_id": client_id,
        "client_secret": CLIENT_SECRET,
    }
    resp = requests.post(url, data=payload, verify=verify_ssl, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["token_type"] + " " + data["access_token"]


def odata_get_all(base_url: str, token: str, verify_ssl: bool, path: str, page_size: int = 1000) -> list:
    results = []
    skip = 0
    sep = "&" if "?" in path else "?"
    while True:
        url = f"{base_url.rstrip('/')}{path}{sep}$top={page_size}&$skip={skip}"
        resp = requests.get(
            url,
            headers={"Authorization": token, "Accept": "application/json", "Content-Type": "application/json;v=1.0"},
            verify=verify_ssl, timeout=120,
        )
        resp.raise_for_status()
        page = resp.json().get("value", [])
        results.extend(page)
        if len(page) < page_size:
            break
        skip += page_size
    return results


def rest_get(base_url: str, token: str, verify_ssl: bool, path: str) -> object:
    resp = requests.get(
        base_url.rstrip("/") + path,
        headers={"Authorization": token, "Accept": "application/json"},
        verify=verify_ssl, timeout=60,
    )
    resp.raise_for_status()
    return resp.json() if resp.content and len(resp.content) > 2 else []


def get_team_map(base_url: str, token: str, verify_ssl: bool) -> dict[int, str]:
    """Return {teamId: fullTeamPath} using GET /cxrestapi/auth/teams.

    The REST API returns Unix-style paths ("/CxServer/Team"); converted here
    to the backslash form used elsewhere in these scripts ("CxServer\\Team").
    """
    teams = rest_get(base_url, token, verify_ssl, f"{REST_BASE}/auth/teams")
    result: dict[int, str] = {}
    for t in (teams if isinstance(teams, list) else []):
        team_id = t.get("id")
        full_name = (t.get("fullName") or t.get("name") or "").lstrip("/").replace("/", "\\")
        if team_id is not None:
            result[team_id] = full_name
    return result


def get_project_map(base_url: str, token: str, verify_ssl: bool, team_map: dict[int, str]) -> dict[int, str]:
    """Return {projectId: fullProjectPath} (TeamPath\\ProjectName) via OData."""
    rows = odata_get_all(
        base_url, token, verify_ssl,
        f"{ODATA_BASE}/Projects?$select=Id,Name,OwningTeamId",
    )
    result: dict[int, str] = {}
    for p in rows:
        team_path = team_map.get(p.get("OwningTeamId"), "")
        name = p.get("Name") or ""
        result[p["Id"]] = f"{team_path}\\{name}" if team_path else name
    return result


def get_soap_client(base_url: str, token: str, verify_ssl: bool) -> Client:
    wsdl = base_url.rstrip("/") + WSDL_PATH
    headers = {"Authorization": token}
    settings = Settings(strict=False, force_https=False, xml_huge_tree=True, extra_http_headers=headers)
    session = Session()
    session.verify = verify_ssl
    transport = Transport(session=session)
    client = Client(wsdl=wsdl, transport=transport, settings=settings)
    client.transport.session.verify = verify_ssl
    return client


def get_all_queries(client: Client) -> list[dict]:
    """Call GetQueryCollection and flatten into a list of query dicts."""
    response = client.service.GetQueryCollection(sessionId="0")
    if not response.IsSuccesfull:
        raise ValueError(f"GetQueryCollection failed: {response.ErrorMessage}")

    queries = []
    if not response.QueryGroups:
        return queries

    for group in response.QueryGroups.CxWSQueryGroup:
        if not group.Queries:
            continue
        language = group.LanguageName or ""
        group_name = group.Name or ""
        for query in group.Queries.CxWSQuery:
            queries.append({
                "QueryId": query.QueryId,
                "Name": query.Name or "",
                "LanguageName": language,
                "GroupName": group_name,
                "PackageType": group.PackageType or "",
                "OwningTeam": group.OwningTeam,
                "ProjectId": group.ProjectId,
            })
    return queries


def resolve_scope(q: dict, team_map: dict[int, str], project_map: dict[int, str]) -> tuple[str, str]:
    """
    Return (scope_kind, scope_identity) describing where a query override
    lives: "corp" (no override), "team", or "project". OwningTeam/ProjectId
    are raw numeric IDs that differ between environments, so they're resolved
    here to a team/project full path, which is comparable across
    environments (CxSAST sets both to 0 for corporate-level queries).
    """
    project_id = q.get("ProjectId") or 0
    owning_team = q.get("OwningTeam") or 0
    if project_id > 0:
        name = project_map.get(project_id)
        return ("project", name if name else f"<unresolved project {project_id}>")
    if owning_team > 0:
        path = team_map.get(owning_team)
        return ("team", path if path else f"<unresolved team {owning_team}>")
    return ("corp", "")


def build_index(
    queries: list[dict],
    label: str,
    team_map: dict[int, str],
    project_map: dict[int, str],
) -> tuple[dict[tuple, int], dict[tuple, list[tuple]]]:
    """
    Returns (index, by_base_key):
      index: (LanguageName, GroupName, QueryName, scope_kind, scope_identity) -> QueryId
      by_base_key: (LanguageName, GroupName, QueryName) -> [(scope_kind, scope_identity, QueryId), ...]

    A query can be overridden at the corporate, team, or project level, with
    each override sharing the same name but getting its own QueryId. Folding
    the override's resolved team/project identity into `index`'s key (instead
    of matching on name alone) lets each override match its equivalent scope
    on the other environment rather than picking an arbitrary one.
    `by_base_key` backs selecting the target's highest-level (most generic)
    override of a given name — see pick_highest_level — since source/target
    team and project structures aren't guaranteed to correspond, so every
    source override of a name maps to that one target override rather than
    trying to match scope-to-scope.
    """
    index = {}
    seen: dict[tuple, list[tuple]] = {}
    for q in queries:
        base_key = (q["LanguageName"].strip(), q["GroupName"].strip(), q["Name"].strip())
        if not all(base_key):
            continue
        scope_kind, scope_identity = resolve_scope(q, team_map, project_map)
        index[base_key + (scope_kind, scope_identity)] = q["QueryId"]
        seen.setdefault(base_key, []).append((scope_kind, scope_identity, q["QueryId"]))
    for base_key, entries in seen.items():
        if len(entries) > 1:
            detail = ", ".join(f"{kind}:{identity or 'cxserver'}=QueryId:{qid}" for kind, identity, qid in entries)
            print(f"  INFO: {label} has {len(entries)} overrides of query {base_key!r}: {detail}", file=sys.stderr)
    return index, seen


def _scope_rank(scope_kind: str, scope_identity: str) -> int:
    """
    Lower rank = higher in the query override hierarchy (closer to the
    corporate/root default). Corporate-level (no team/project) ranks
    highest; team-level overrides rank by how many path segments deep the
    owning team is, so a root team ("CxServer") outranks a sub-team
    ("CxServer\\Team5"); project-level overrides always rank lowest, since
    they're the most specific kind of override.
    """
    if scope_kind == "corp":
        return 0
    if scope_kind == "team":
        return scope_identity.count("\\") + 1 if scope_identity else 1
    return 10_000


def pick_highest_level(candidates: list[tuple]) -> tuple:
    """
    Given [(scope_kind, scope_identity, QueryId), ...] for same-named query
    overrides, return the one highest in the override hierarchy (deterministic
    tie-break: scope_identity, then QueryId).
    """
    return min(candidates, key=lambda c: (_scope_rank(c[0], c[1]), c[1] or "", c[2]))


def load_env(var: str, label: str) -> str:
    val = os.getenv(var, "").strip()
    if not val:
        print(f"ERROR: {label} is not set. Configure {var} in .env or as an environment variable.", file=sys.stderr)
        sys.exit(1)
    return val


def main():
    parser = argparse.ArgumentParser(description="Generate SAST query ID mapping between two environments.")
    parser.add_argument("--output", default=os.getenv("OUTPUT_FILE", "mapping.json"), help="Output JSON file path")
    args = parser.parse_args()

    source_url  = load_env("SOURCE_URL",      "Source environment URL")
    source_user = load_env("SOURCE_USERNAME", "Source username")
    source_pass = load_env("SOURCE_PASSWORD", "Source password")
    target_url  = load_env("TARGET_URL",      "Target environment URL")
    target_user = load_env("TARGET_USERNAME", "Target username")
    target_pass = load_env("TARGET_PASSWORD", "Target password")
    verify_ssl  = os.getenv("VERIFY_SSL", "true").strip().lower() != "false"

    if not verify_ssl:
        disable_warnings(InsecureRequestWarning)
        print("WARNING: SSL verification is disabled.", file=sys.stderr)

    print(f"Authenticating to source: {source_url}")
    source_token = get_bearer_token(source_url, source_user, source_pass, verify_ssl)
    source_odata_token = get_bearer_token(source_url, source_user, source_pass, verify_ssl,
                                           scope=ODATA_SCOPE, client_id=ODATA_CLIENT)

    print(f"Authenticating to target: {target_url}")
    target_token = get_bearer_token(target_url, target_user, target_pass, verify_ssl)
    target_odata_token = get_bearer_token(target_url, target_user, target_pass, verify_ssl,
                                           scope=ODATA_SCOPE, client_id=ODATA_CLIENT)

    print("Connecting SOAP client to source environment...")
    source_client = get_soap_client(source_url, source_token, verify_ssl)

    print("Connecting SOAP client to target environment...")
    target_client = get_soap_client(target_url, target_token, verify_ssl)

    print("Fetching team/project paths from source (for resolving query override scope)...")
    source_team_map = get_team_map(source_url, source_odata_token, verify_ssl)
    source_project_map = get_project_map(source_url, source_odata_token, verify_ssl, source_team_map)

    print("Fetching team/project paths from target (for resolving query override scope)...")
    target_team_map = get_team_map(target_url, target_odata_token, verify_ssl)
    target_project_map = get_project_map(target_url, target_odata_token, verify_ssl, target_team_map)

    print("Fetching query collection from source...")
    source_queries = get_all_queries(source_client)
    print(f"  Found {len(source_queries)} queries in source")

    print("Fetching query collection from target...")
    target_queries = get_all_queries(target_client)
    print(f"  Found {len(target_queries)} queries in target")

    source_index, _source_by_base = build_index(source_queries, "source", source_team_map, source_project_map)
    target_index, target_by_base = build_index(target_queries, "target", target_team_map, target_project_map)

    mappings = []
    unmatched_source = []
    unmatched_target = set(target_index.keys())

    for key, source_id in sorted(source_index.items(), key=lambda x: x[1]):
        base_key, scope_kind, scope_identity = key[:3], key[3], key[4]

        # Always map to the target's highest-level override of this query —
        # not whichever target team/project happens to share the source
        # override's scope. Source and target team/project structures aren't
        # guaranteed to correspond 1:1, so matching scope-to-scope can pick an
        # unrelated override; the override hierarchy's top (corporate, or the
        # closest-to-root team) is the one every project inherits from unless
        # specifically customized, making it the one safe, predictable choice
        # regardless of which override the source result's query happens to be.
        candidates = target_by_base.get(base_key, [])
        if not candidates:
            unmatched_source.append({
                "queryId": source_id,
                "language": base_key[0],
                "group": base_key[1],
                "queryName": base_key[2],
            })
            continue

        chosen_kind, chosen_identity, target_id = pick_highest_level(candidates)
        mappings.append({
            "sourceQueryId": str(source_id),
            "targetQueryId": str(target_id),
            "language": base_key[0],
            "group": base_key[1],
            "queryName": base_key[2],
        })
        unmatched_target.discard(base_key + (chosen_kind, chosen_identity))
        if len(candidates) > 1 and (scope_kind, scope_identity) != (chosen_kind, chosen_identity):
            print(f"  NOTE: [{source_id}] {base_key[0]}/{base_key[1]}/{base_key[2]} "
                  f"({scope_kind}:{scope_identity or 'cxserver'}) mapped to target's highest-level "
                  f"override ({chosen_kind}:{chosen_identity or 'cxserver'}) QueryId={target_id}",
                  file=sys.stderr)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"mappings": mappings}, f, indent=2)

    print(f"\nDone. Wrote {len(mappings)} mappings to {args.output}")

    if unmatched_source:
        print(f"\nWARNING: {len(unmatched_source)} source queries have no match in target:")
        for q in unmatched_source[:20]:
            print(f"  [{q['queryId']}] {q['language']} / {q['group']} / {q['queryName']}")
        if len(unmatched_source) > 20:
            print(f"  ... and {len(unmatched_source) - 20} more")

    if unmatched_target:
        print(f"\nINFO: {len(unmatched_target)} target queries have no corresponding source query:")
        for key in sorted(unmatched_target)[:20]:
            scope = f"{key[3]}:{key[4]}" if key[4] else key[3]
            print(f"  [{target_index[key]}] {key[0]} / {key[1]} / {key[2]} ({scope})")
        if len(unmatched_target) > 20:
            print(f"  ... and {len(unmatched_target) - 20} more")


if __name__ == "__main__":
    main()
