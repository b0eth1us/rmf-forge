"""
Offline CWE -> CCI -> NIST 800-53 mapper.
Loads CCI XML from backend/data/cci/ — zero network calls.
Accepts either U_CCI_List.xml or CCI_List.xml filename.
"""
import json
import os
import re
from functools import lru_cache
from lxml import etree
from typing import Any

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")


def _find_cci_file() -> str | None:
    """Find the CCI XML file regardless of exact filename."""
    cci_dir = os.path.join(DATA_DIR, "cci")
    if not os.path.isdir(cci_dir):
        return None
    # Accept any XML file in the cci directory
    for candidate in ["U_CCI_List.xml", "CCI_List.xml"]:
        path = os.path.join(cci_dir, candidate)
        if os.path.exists(path):
            return path
    # Fall back to any .xml file present
    for fname in os.listdir(cci_dir):
        if fname.lower().endswith(".xml"):
            return os.path.join(cci_dir, fname)
    return None


@lru_cache(maxsize=1)
def load_cci_index() -> dict[str, dict[str, Any]]:
    """
    Parse CCI XML into {cci_id: {definition, controls: [nist_id, ...], nist_control}}
    """
    cci_file = _find_cci_file()
    if not cci_file:
        return {}

    try:
        tree = etree.parse(cci_file)
        root = tree.getroot()
    except Exception as e:
        print(f"[cci_mapper] Failed to parse CCI file: {e}")
        return {}

    # Try known DISA CCI namespaces in order
    items = []
    ns = {}
    for ns_uri in [
        "http://iase.disa.mil/cci",
        "http://csrc.nist.gov/ns/oscal/1.0",
        "",
    ]:
        if ns_uri:
            ns = {"cci": ns_uri}
            items = root.findall(".//cci:cci_item", ns)
        else:
            ns = {}
            items = root.findall(".//cci_item")
        if items:
            break

    if not items:
        print(f"[cci_mapper] No cci_item elements found in {cci_file}")
        return {}

    index = {}
    for item in items:
        cci_id = item.get("id", "")
        if not cci_id:
            continue

        if ns:
            definition = item.findtext("cci:definition", namespaces=ns) or ""
            controls = [
                ref.get("index", "") or ref.get("identifier", "")
                for ref in item.findall(".//cci:reference", ns)
                if ref.get("index") or ref.get("identifier")
            ]
        else:
            definition = item.findtext("definition") or ""
            controls = [
                ref.get("index", "") or ref.get("identifier", "")
                for ref in item.findall(".//reference")
                if ref.get("index") or ref.get("identifier")
            ]

        index[cci_id] = {
            "definition": definition,
            "controls": controls,
            "nist_control": controls[0] if controls else "",
        }

    print(f"[cci_mapper] Loaded {len(index)} CCI items from {os.path.basename(cci_file)}")
    return index


@lru_cache(maxsize=1)
def load_cwe_cci_map() -> dict[str, list[str]]:
    """Load hand-curated CWE->CCI JSON map from data/cwe/cwe_cci_map.json"""
    map_file = os.path.join(DATA_DIR, "cwe", "cwe_cci_map.json")
    if not os.path.exists(map_file):
        return {}
    with open(map_file) as f:
        data = json.load(f)
    # Remove the _comment key if present
    data.pop("_comment", None)
    return data


def map_cwe_to_ccis(cwe_id: str) -> list[dict[str, Any]]:
    """
    Given a CWE ID (bare number or 'CWE-NNN'), return list of matching CCI dicts.
    Each dict: {cci_id, definition, controls, nist_control}
    """
    if not cwe_id:
        return []

    # Normalize: strip any non-numeric prefix, get bare number
    bare = re.sub(r'[^0-9]', '', str(cwe_id).split('.')[0])
    if not bare:
        return []

    cwe_map = load_cwe_cci_map()
    cci_index = load_cci_index()

    # Try multiple key formats
    cci_ids = (
            cwe_map.get(bare) or
            cwe_map.get(f"CWE-{bare}") or
            cwe_map.get(f"cwe-{bare}") or
            []
    )

    if not cci_ids:
        return []

    result = []
    for cid in cci_ids:
        if cid in cci_index:
            result.append({"cci_id": cid, **cci_index[cid]})
        else:
            # CCI ID is in our map but not in the loaded index — include with minimal info
            result.append({"cci_id": cid, "definition": "", "controls": [], "nist_control": ""})

    return result


def get_unmapped_cwe_ids(cwe_ids: list[str]) -> list[str]:
    """Return CWE IDs that have no CCI mapping in cwe_cci_map.json."""
    return [c for c in cwe_ids if not map_cwe_to_ccis(c)]