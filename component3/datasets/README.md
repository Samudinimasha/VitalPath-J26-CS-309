# Baseline vital-sign recordings

Real, de-identified vital-sign numerics used as the legitimate ("normal")
telemetry stream for the Component 3 simulator and evaluation. Converted from
PhysioNet exports with `simulator/physionet_xlsx_to_csv.py`.

CSV columns: `t_s` (seconds from start), `hr`, `pulse`, `spo2`, `sbp`, `dbp`, `resp`.
An empty cell means no reading at that time. Blood pressure is the
non-invasive cuff (NBP).

| File | Source | Record | Length | Interval |
|---|---|---|---|---|
| `mimic3wdb_3000003n.csv` | MIMIC-III Waveform Database v1.0 | 3000003n | 42 h | 1 min |
| `mimic3wdb_3105145n.csv` | MIMIC-III Waveform Database v1.0 | 3105145n | 29 h | 1 min |
| `bidmc_53n.csv` | BIDMC PPG and Respiration Dataset v1.0.0 | bidmc53n | 8 min | 1 s |

## Licences

- MIMIC-III Waveform Database files: Open Data Commons Open Database License
  (ODbL) v1.0. The two `mimic3wdb_*.csv` files are derived from that database
  and are distributed under ODbL v1.0.
- BIDMC file: Open Data Commons Attribution License v1.0.

The ODbL applies to these data files only, not to the VitalPath source code.

## Citations

1. Moody, B., Moody, G., Villarroel, M., Clifford, G. D., & Silva, I. (2020).
   MIMIC-III Waveform Database (version 1.0). PhysioNet.
   https://doi.org/10.13026/c2607m
2. Johnson, A. E. W. et al. (2016). MIMIC-III, a freely accessible critical
   care database. Scientific Data, 3, 160035.
   https://doi.org/10.1038/sdata.2016.35
3. Pimentel, M. A. F. et al. (2016). Towards a robust estimation of
   respiratory rate from pulse oximeters. IEEE Transactions on Biomedical
   Engineering, 64(8), 1914-1923. https://doi.org/10.1109/TBME.2016.2613124
4. Pollard, T. et al. (2026). PhysioNet as a global platform for biomedical
   research. Nature Health. https://doi.org/10.1038/s44360-026-00096-z
