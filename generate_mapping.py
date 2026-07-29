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
CLIENT_SECRET = "014DF517-39D1-4453-B7B3-9930C563627C"


def get_bearer_token(base_url: str, username: str, password: str, verify_ssl: bool) -> str:
    url = base_url.rstrip("/") + TOKEN_PATH
    payload = {
        "username": username,
        "password": password,
        "grant_type": "password",
        "scope": SOAP_SCOPE,
        "client_id": SOAP_CLIENT,
        "client_secret": CLIENT_SECRET,
    }
    resp = requests.post(url, data=payload, verify=verify_ssl, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    return data["token_type"] + " " + data["access_token"]


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
            })
    return queries


def build_index(queries: list[dict]) -> dict[tuple, int]:
    """Key: (LanguageName, GroupName, QueryName) -> QueryId."""
    index = {}
    for q in queries:
        key = (q["LanguageName"].strip(), q["GroupName"].strip(), q["Name"].strip())
        if all(key):
            index[key] = q["QueryId"]
    return index


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

    print(f"Authenticating to target: {target_url}")
    target_token = get_bearer_token(target_url, target_user, target_pass, verify_ssl)

    print("Connecting SOAP client to source environment...")
    source_client = get_soap_client(source_url, source_token, verify_ssl)

    print("Connecting SOAP client to target environment...")
    target_client = get_soap_client(target_url, target_token, verify_ssl)

    print("Fetching query collection from source...")
    source_queries = get_all_queries(source_client)
    print(f"  Found {len(source_queries)} queries in source")

    print("Fetching query collection from target...")
    target_queries = get_all_queries(target_client)
    print(f"  Found {len(target_queries)} queries in target")

    source_index = build_index(source_queries)
    target_index = build_index(target_queries)

    mappings = []
    unmatched_source = []
    unmatched_target = set(target_index.keys())

    for key, source_id in sorted(source_index.items(), key=lambda x: x[1]):
        if key in target_index:
            mappings.append({
                "sourceQueryId": str(source_id),
                "targetQueryId": str(target_index[key]),
                "language": key[0],
                "group": key[1],
                "queryName": key[2],
            })
            unmatched_target.discard(key)
        else:
            unmatched_source.append({
                "queryId": source_id,
                "language": key[0],
                "group": key[1],
                "queryName": key[2],
            })

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
            print(f"  [{target_index[key]}] {key[0]} / {key[1]} / {key[2]}")
        if len(unmatched_target) > 20:
            print(f"  ... and {len(unmatched_target) - 20} more")


if __name__ == "__main__":
    main()
