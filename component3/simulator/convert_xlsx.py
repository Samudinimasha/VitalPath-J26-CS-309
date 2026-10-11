"""Convert PhysioNet numerics exported to .xlsx into the simulator's CSV format.

Usage (from component3/):
    PYTHONPATH=src python3 -m simulator.convert_xlsx SOURCE.xlsx PROFILE OUT.csv

PROFILE says how to read each export (column names, how missing values are
written). Column A is elapsed time in days, as exported by PhysioNet.
Standard library only, so no Excel or openpyxl is needed.
"""

import argparse
import csv
import re
import xml.etree.ElementTree as ET
import zipfile

from vitalpath_c3.data.loaders import CSV_COLUMNS

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}

# Output column -> source header. Blood pressure uses the non-invasive cuff
# (NBP), which is what an ambulance monitor provides.
PROFILES = {
    # MIMIC-III Waveform Database record 3000003n: 0 means no reading.
    "mimic3wdb-3000003n": {
        "zero_is_missing": True,
        "columns": {"hr": "HR", "pulse": "PULSE", "spo2": "SpO2",
                    "sbp": "NBPSys", "dbp": "NBPDias", "resp": "RESP"},
    },
    # MIMIC-III Waveform Database record 3105145n: empty cell means no reading.
    "mimic3wdb-3105145n": {
        "zero_is_missing": False,
        "columns": {"hr": "HR", "pulse": "PULSE", "spo2": "%SpO2",
                    "sbp": "NBP SYS", "dbp": "NBP DIAS", "resp": "RESP"},
    },
    # BIDMC PPG and Respiration Dataset record bidmc53n (1 Hz numerics).
    "bidmc-53n": {
        "zero_is_missing": False,
        "columns": {"hr": "HR,", "pulse": "PULSE,", "spo2": "SpO2,", "resp": "RESP,"},
    },
}


def read_sheet(path):
    """Yield each row of the first worksheet as {column letter: value}."""
    with zipfile.ZipFile(path) as zf:
        strings = []
        if "xl/sharedStrings.xml" in zf.namelist():
            root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
            strings = ["".join(t.text or "" for t in si.iter(f"{{{_NS['m']}}}t"))
                       for si in root.findall("m:si", _NS)]
        sheet = ET.fromstring(zf.read("xl/worksheets/sheet1.xml"))
    for row in sheet.iter(f"{{{_NS['m']}}}row"):
        cells = {}
        for c in row.findall("m:c", _NS):
            v = c.find("m:v", _NS)
            if v is None:
                continue
            letter = re.match(r"[A-Z]+", c.get("r")).group()
            cells[letter] = strings[int(v.text)] if c.get("t") == "s" else float(v.text)
        yield cells


def convert(source, profile_name, out):
    profile = PROFILES[profile_name]
    rows = read_sheet(source)
    header = next(rows)
    by_name = {name: letter for letter, name in header.items()}
    letters = {}
    for col, name in profile["columns"].items():
        if name not in by_name:
            raise SystemExit(f"{source}: column {name!r} not found")
        letters[col] = by_name[name]

    written = 0
    with open(out, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_COLUMNS)
        for cells in rows:
            if "A" not in cells:
                continue
            out_row = [round(cells["A"] * 86400, 3)]
            for col in CSV_COLUMNS[1:]:
                value = cells.get(letters[col]) if col in letters else None
                if value is None or (profile["zero_is_missing"] and value == 0):
                    out_row.append("")
                else:
                    out_row.append(round(value, 2))
            writer.writerow(out_row)
            written += 1
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source")
    parser.add_argument("profile", choices=sorted(PROFILES))
    parser.add_argument("out")
    args = parser.parse_args()
    n = convert(args.source, args.profile, args.out)
    print(f"Wrote {n} rows to {args.out}")


if __name__ == "__main__":
    main()
