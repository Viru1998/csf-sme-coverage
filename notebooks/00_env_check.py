"""
Environment + raw-data smoke test.
Run from the project root with the csf-sme-coverage env activated:
    python notebooks/00_env_check.py
"""
import sys
import time
import importlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"

OK   = "  [OK]   "
FAIL = "  [FAIL] "

passed, failed = 0, 0

def check(label, fn):
    """Run fn(); record pass/fail; print one line."""
    global passed, failed
    t0 = time.time()
    try:
        result = fn()
        dt = (time.time() - t0) * 1000
        print(f"{OK}{label:<46s}  {result}   ({dt:.0f} ms)")
        passed += 1
    except Exception as e:
        dt = (time.time() - t0) * 1000
        print(f"{FAIL}{label:<46s}  {type(e).__name__}: {e}   ({dt:.0f} ms)")
        failed += 1

def section(title):
    print(f"\n=== {title} ===")

# ---- 1. Python version ----
section("1. Python interpreter")
check("Python >= 3.12",
      lambda: f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}")

# ---- 2. Library imports ----
section("2. Library imports")
LIBS = [
    "pandas", "numpy", "matplotlib", "seaborn", "scipy",
    "openpyxl", "pdfplumber", "stix2", "mitreattack", "requests", "pytest",
]
for name in LIBS:
    def go(mod=name):
        m = importlib.import_module(mod)
        return getattr(m, "__version__", "(no __version__)")
    check(name, go)

# ---- 3. Data files present ----
section("3. Raw data files present")
files = [
    "csf2_core.json",
    "csf2_to_800_53_rev5.xlsx",
    "ctid_nist800_53_attack16.1.json",
    "enterprise-attack-16.1.json",
    "verizon_dbir_2026.pdf",
    "enisa_threat_landscape_2024.pdf",
    "mtu_ncsc_state_of_sector_2025.pdf",
    "ncsc_ireland_sme_guidance_2025.pdf",
]
for f in files:
    def go(name=f):
        p = RAW / name
        if not p.exists():
            raise FileNotFoundError(p)
        return f"{p.stat().st_size/1024/1024:.2f} MB"
    check(f, go)

# ---- 4. Each file loads cleanly with the right library ----
section("4. Raw data loadable")
import json

def load_csf():
    d = json.load(open(RAW / "csf2_core.json", encoding="utf-8"))
    elems = d["response"]["elements"]["elements"]
    subs = [e for e in elems if e.get("element_type") == "subcategory"]
    return f"{len(subs)} subcategory elements (incl. withdrawn)"
check("csf2_core.json -> json", load_csf)

def load_crosswalk():
    import openpyxl, re
    wb = openpyxl.load_workbook(RAW / "csf2_to_800_53_rev5.xlsx", read_only=True)
    ws = wb["Relationships"]
    sub_pat = re.compile(r"^[A-Z]{2}\.[A-Z]{2}-\d+$")
    rows = 0
    subs = set()
    for i, row in enumerate(ws.iter_rows(values_only=True)):
        if i == 0:
            continue
        csf = str(row[0]).strip() if row[0] else ""
        if sub_pat.match(csf):
            rows += 1
            subs.add(csf)
    return f"{rows} sub->control rows, {len(subs)} unique subcats"
check("csf2_to_800_53_rev5.xlsx -> openpyxl", load_crosswalk)

def load_ctid():
    d = json.load(open(RAW / "ctid_nist800_53_attack16.1.json", encoding="utf-8"))
    return f"{len(d['mapping_objects'])} mapping objects"
check("ctid_nist800_53_attack16.1.json -> json", load_ctid)

def load_attack():
    d = json.load(open(RAW / "enterprise-attack-16.1.json", encoding="utf-8"))
    techs = sum(1 for o in d["objects"] if o.get("type") == "attack-pattern")
    return f"{techs} techniques in STIX bundle"
check("enterprise-attack-16.1.json -> stix bundle", load_attack)

def load_pdf(name):
    import pdfplumber
    with pdfplumber.open(RAW / name) as pdf:
        n = len(pdf.pages)
    return f"{n} pages"

for pdf in [
    "verizon_dbir_2026.pdf",
    "enisa_threat_landscape_2024.pdf",
    "mtu_ncsc_state_of_sector_2025.pdf",
    "ncsc_ireland_sme_guidance_2025.pdf",
]:
    check(f"{pdf} -> pdfplumber", lambda p=pdf: load_pdf(p))

# ---- summary ----
section("Summary")
print(f"  Passed: {passed}")
print(f"  Failed: {failed}")
if failed == 0:
    print("\n  Environment is healthy. You can proceed to building the real pipeline.")
else:
    print("\n  Some checks failed - investigate the [FAIL] lines above before proceeding.")
    sys.exit(1)
