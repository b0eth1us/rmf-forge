"""
Management command: generate_cwe_cci_map
========================================
Builds a comprehensive CWE -> CCI mapping JSON by joining two sources:

  1. MITRE Heimdall's CWE->NIST 800-53 CSV  (downloaded from GitHub)
  2. Your local DISA CCI_List.xml            (already in backend/data/cci/)

Chain: CWE -> NIST 800-53 control -> CCI ID

Usage (from project root or inside container):
  python -m app.management.generate_cwe_cci_map
  python -m app.management.generate_cwe_cci_map --dry-run
  python -m app.management.generate_cwe_cci_map --output /custom/path/cwe_cci_map.json
"""

import argparse
import csv
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
# Inside the container the app lives at /app, so data is at /app/data
# Outside the container (local dev) it's relative to this file's location
_CONTAINER_DATA = Path("/app/data")
_LOCAL_DATA = Path(__file__).resolve().parents[3] / "data"
DATA_DIR = _CONTAINER_DATA if _CONTAINER_DATA.exists() else _LOCAL_DATA
CCI_DIR = DATA_DIR / "cci"
CWE_DIR = DATA_DIR / "cwe"
DEFAULT_OUTPUT = CWE_DIR / "cwe_cci_map.json"

# MITRE Heimdall's authoritative CWE->NIST 800-53 mapping CSV
CWE_NIST_CSV_URL = (
    "https://raw.githubusercontent.com/mitre/heimdall_tools/"
    "master/lib/data/cwe-nist-mapping.csv"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_cci_xml() -> Path:
    """Return the first .xml file found in the CCI data directory."""
    candidates = list(CCI_DIR.glob("*.xml"))
    if not candidates:
        print(f"[ERROR] No CCI XML file found in {CCI_DIR}", file=sys.stderr)
        sys.exit(1)
    if len(candidates) > 1:
        print(f"[WARN] Multiple CCI XML files found, using: {candidates[0].name}")
    return candidates[0]


def _normalize_nist(ctrl: str) -> list[str]:
    """
    Return several normalized variants of a NIST control string so we can
    fuzzy-match across the two sources (which use slightly different formats).

    Examples:
        "SI-10 (3)" -> ["SI-10 (3)", "SI-10(3)", "SI-10 (3) ", "si-10 (3)"]
        "AC-2"      -> ["AC-2", "AC-2 ", "ac-2"]
    """
    ctrl = ctrl.strip()
    variants = {
        ctrl,
        ctrl.replace(" ", ""),           # "SI-10(3)"
        ctrl.upper(),
        ctrl.lower(),
        re.sub(r'\s*\(', ' (', ctrl),    # normalise spacing before parens
        re.sub(r'\s+', ' ', ctrl),       # collapse internal whitespace
    }
    return list(variants)


def _download_cwe_nist_csv(url: str) -> list[dict]:
    """Download the MITRE CWE->NIST CSV and return parsed rows."""
    print(f"[1/3] Downloading CWE->NIST mapping from MITRE Heimdall...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "rmf-forge/1.0"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[ERROR] Download failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Strip UTF-8 BOM if present — MITRE's CSV starts with \ufeff
    raw = raw.lstrip("\ufeff")
    reader = csv.DictReader(raw.splitlines())
    rows = list(reader)
    print(f"       Downloaded {len(rows)} rows.")
    return rows


def _build_cwe_to_nist(rows: list[dict]) -> dict[str, set[str]]:
    """
    Parse CSV rows into {cwe_bare_number: {nist_control, ...}}.
    Handles multiple controls per CWE separated by commas/semicolons.
    """
    cwe_to_nist: dict[str, set[str]] = defaultdict(set)

    for row in rows:
        # Actual columns: 'CWE-ID', 'CWE Name', 'NIST-ID', 'Rev', 'NIST Name'
        # (BOM stripped above so no \ufeff prefix)
        raw_cwe = (
                row.get("CWE-ID") or row.get("CWE_ID") or row.get("cwe_id") or ""
        ).strip()
        raw_nist = (
                row.get("NIST-ID") or row.get("NIST-800-53") or row.get("NIST_800_53") or ""
        ).strip()

        if not raw_cwe or not raw_nist:
            continue

        # Normalise CWE: strip prefix and decimal  e.g. "CWE-89.0" -> "89"
        bare_cwe = re.sub(r"[^0-9]", "", raw_cwe.split(".")[0])
        if not bare_cwe or bare_cwe == "0":
            continue

        # Controls can be comma/semicolon separated
        for ctrl in re.split(r"[,;]", raw_nist):
            ctrl = ctrl.strip()
            if ctrl:
                cwe_to_nist[bare_cwe].add(ctrl)

    return dict(cwe_to_nist)


def _parse_cci_xml(cci_file: Path) -> dict[str, list[str]]:
    """
    Parse CCI_List.xml into {nist_control_variant: [cci_ids]}.
    Indexes every normalised variant so fuzzy matching works.
    """
    print(f"[2/3] Parsing {cci_file.name}...")
    tree = ET.parse(cci_file)
    root = tree.getroot()

    # Detect namespace
    ns_match = re.match(r"\{(.+)\}", root.tag)
    ns = ns_match.group(1) if ns_match else ""
    ns_prefix = f"{{{ns}}}" if ns else ""

    nist_to_ccis: dict[str, list[str]] = defaultdict(list)

    for item in root.iter(f"{ns_prefix}cci-item"):
        cci_id = item.get("id", "").strip()
        if not cci_id:
            continue
        for ref in item.iter(f"{ns_prefix}reference"):
            ctrl = (ref.get("index") or ref.get("identifier") or "").strip()
            if not ctrl:
                continue
            for variant in _normalize_nist(ctrl):
                nist_to_ccis[variant].append(cci_id)

    # Deduplicate within each list
    result = {k: sorted(set(v)) for k, v in nist_to_ccis.items()}
    print(f"       Indexed {len(result)} NIST control variants.")
    return result


def _join_mappings(
        cwe_to_nist: dict[str, set[str]],
        nist_to_ccis: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Join CWE->NIST and NIST->CCI to produce CWE->CCI."""
    print("[3/3] Joining CWE->NIST->CCI...")

    cwe_cci: dict[str, list[str]] = {}
    unmapped_cwes = []

    for cwe, nist_controls in sorted(
            cwe_to_nist.items(), key=lambda x: int(x[0]) if x[0].isdigit() else 999999
    ):
        ccis: set[str] = set()
        for ctrl in nist_controls:
            for variant in _normalize_nist(ctrl):
                ccis.update(nist_to_ccis.get(variant, []))

        if ccis:
            cwe_cci[cwe] = sorted(ccis)
        else:
            unmapped_cwes.append(cwe)

    print(f"       Mapped:   {len(cwe_cci)} CWEs")
    print(f"       Unmapped: {len(unmapped_cwes)} CWEs (no CCI found for their NIST controls)")
    if unmapped_cwes[:10]:
        print(f"       Unmapped sample: {unmapped_cwes[:10]}")

    return cwe_cci


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(output_path: Path, dry_run: bool = False) -> None:
    print("=" * 60)
    print("RMF Forge — CWE->CCI Map Generator")
    print("=" * 60)

    rows = _download_cwe_nist_csv(CWE_NIST_CSV_URL)
    cwe_to_nist = _build_cwe_to_nist(rows)
    print(f"       Parsed {len(cwe_to_nist)} unique CWEs from CSV.")

    cci_file = _find_cci_xml()
    nist_to_ccis = _parse_cci_xml(cci_file)

    cwe_cci = _join_mappings(cwe_to_nist, nist_to_ccis)

    output = {
        "_comment": (
            "Auto-generated by app.management.generate_cwe_cci_map. "
            "Source: MITRE Heimdall CWE-NIST CSV + DISA CCI_List.xml. "
            "Re-run with: python -m app.management.generate_cwe_cci_map"
        ),
        **cwe_cci,
    }

    if dry_run:
        print("\n[DRY RUN] Would write to:", output_path)
        print(f"[DRY RUN] Sample output (first 5 entries):")
        for k, v in list(cwe_cci.items())[:5]:
            print(f"  CWE-{k}: {v}")
        return

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    size_kb = output_path.stat().st_size // 1024
    print(f"\n[DONE] Written {len(cwe_cci)} CWE mappings to {output_path} ({size_kb} KB)")
    print(
        "\nNOTE: Restart the backend container to clear lru_cache and pick up the new map:\n"
        "  docker compose restart backend"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate comprehensive CWE->CCI mapping JSON for RMF Forge."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output path for JSON file (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Download and process data but do not write the output file.",
    )
    args = parser.parse_args()
    run(output_path=args.output, dry_run=args.dry_run)


if __name__ == "__main__":
    main()