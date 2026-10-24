"""Load baseline vital-sign recordings prepared by simulator/physionet_xlsx_to_csv.py.

CSV columns: t_s, hr, pulse, spo2, sbp, dbp, resp. An empty cell means no
reading at that time.
"""

import csv
from pathlib import Path
from typing import List, Tuple, Union

from vitalpath_c3.packet_models import VitalSigns

CSV_COLUMNS = ("t_s", "hr", "pulse", "spo2", "sbp", "dbp", "resp")


def load_vitals_csv(path: Union[str, Path]) -> List[Tuple[float, VitalSigns]]:
    """Return (seconds from start of recording, vitals) for each row."""
    rows = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        missing = set(CSV_COLUMNS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"{path}: missing columns {sorted(missing)}")
        for line in reader:
            values = {k: float(line[k]) if line[k] else None for k in CSV_COLUMNS[1:]}
            rows.append((float(line["t_s"]), VitalSigns(**values)))
    return rows
