import pytest

from vitalpath_c3.data.physionet_loader import load_vitals_csv
from vitalpath_c3.packet_models import VitalSigns


def test_load_vitals_csv(tmp_path):
    path = tmp_path / "rec.csv"
    path.write_text(
        "t_s,hr,pulse,spo2,sbp,dbp,resp\n"
        "0.0,85.0,84.0,98.0,,,18.0\n"
        "1.0,,,,120.0,80.0,\n"
    )
    assert load_vitals_csv(path) == [
        (0.0, VitalSigns(hr=85.0, pulse=84.0, spo2=98.0, resp=18.0)),
        (1.0, VitalSigns(sbp=120.0, dbp=80.0)),
    ]


def test_missing_column_rejected(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text("t_s,hr\n0,80\n")
    with pytest.raises(ValueError, match="missing columns"):
        load_vitals_csv(path)
