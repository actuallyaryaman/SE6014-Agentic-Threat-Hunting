# OTRF fixture provenance

The two small fixtures in this directory come from the
[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) repository.
They are committed so Group B tests can run offline without downloading or
unzipping data during CI.

**Pinned upstream commit:** `d9d40ef123d2c87d5d3df28c96bcab4f0faccc87`
(2026-10-23).

| Local file | Dataset ID | Title | Original file | Rows | ATT&CK |
|---|---|---|---|---|---|
| `AWS_S3_HoneyBucketLogs.csv` | `SDAWS-2202181000` | AWS S3 Honey Bucket Logs | `AWS_S3_HoneyBucketLogs.csv` | 301 data rows | T1580 |
| `sh_arp_cache_2020-11-10074812.auditd` | `SDLIN-201110074812` | Arp Cache Discovery | `sh_arp_cache_2020-11-10074812.log` | 12 lines | T1018 |

Source archives at the pinned commit:

- <https://github.com/OTRF/Security-Datasets/tree/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/aws/discovery>
- <https://github.com/OTRF/Security-Datasets/tree/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/linux/discovery/host>

Dataset metadata at the pinned commit:

- <https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/_metadata/SDAWS-2202181000.yaml>
- <https://github.com/OTRF/Security-Datasets/blob/d9d40ef123d2c87d5d3df28c96bcab4f0faccc87/datasets/atomic/_metadata/SDLIN-201110074812.yaml>

The AWS dataset covers S3 public-bucket discovery (T1580). The Linux dataset
covers ARP-cache discovery (T1018). Both are attack simulations; they do not
contain live malware.

The auditd fixture was renamed from `.log` to `.auditd` because the repository
ignores `*.log` files. Its content is unchanged; see `SHA256SUMS`.

## Licensing

Upstream presents conflicting licence signals at the pinned commit: its
`README.md` says `License: GPL-3.0`, while its `LICENSE` file and GitHub's
licence API report MIT. The upstream MIT text is included as
`UPSTREAM-LICENSE-MIT.txt`. See `LICENSE-NOTICE.md` before redistributing
these samples outside this coursework repository.

## Refresh

From the repository root:

```bash
python group_B/scripts/fetch_otrf_fixtures.py --check
python group_B/scripts/fetch_otrf_fixtures.py --force
```

The script downloads from the pinned commit and refuses to write a file whose
SHA-256 does not match the pinned value in
`group_B/scripts/fetch_otrf_fixtures.py`. The test suite also checks
`SHA256SUMS`.
