"""
Offline CWE -> CCI mapper.
Loads the bundled DoD U_CCI_List.xml and a hand-curated CWE->CCI index.
Zero network calls.
"""
import json
import os
from functools import lru_cache
from lxml import etree
from typing import Any

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")

@lru_cache(maxsize=1)
def load_cci_index() -> dict[str, dict[str, Any]]:
    """Returns {cci_id: {definition, control_ids, ...}}"""
    cci_file = os.path.join(DATA_DIR, "cci", "U_CCI_List.xml")
    if not os.path.exists(cci_file):
        return {}
    tree = etree.parse(cci_file)
    root = tree.getroot()
    ns = {"cci": "http://iase.disa.mil/cci"}
    index = {}
    for item in root.findall(".//cci:cci_item", ns):
        cci_id = item.get("id", "")
        definition = item.findtext("cci:definition", namespaces=ns) or ""
        controls = [r.get("index", "") for r in item.findall(".//cci:reference", ns)]
        index[cci_id] = {"definition": definition, "controls": controls}
    return index

@lru_cache(maxsize=1)
def load_cwe_cci_map() -> dict[str, list[str]]:
    """Returns {cwe_id: [cci_id, ...]} from bundled JSON mapping."""
    map_file = os.path.join(DATA_DIR, "cwe", "cwe_cci_map.json")
    if not os.path.exists(map_file):
        return {}
    with open(map_file) as f:
        return json.load(f)

def map_cwe_to_ccis(cwe_id: str) -> list[dict[str, Any]]:
    """Returns list of CCI dicts for a given CWE ID."""
    cwe_map = load_cwe_cci_map()
    cci_index = load_cci_index()
    cci_ids = cwe_map.get(str(cwe_id), cwe_map.get(f"CWE-{cwe_id}", []))
    return [{"cci_id": cid, **cci_index.get(cid, {})} for cid in cci_ids]
