# On fair and realistic performance evaluations for graph-based lateral movement detectors

This repository contains preprocessing and labeling scripts for the LANL "Comprehensive,
multi-source cyber-security events" and DARPA "Operationally transparent cyber" datasets.
The preprocessing and labeling are specifically designed for evaluating lateral
movement detectors :
- LANL: `extract_lanl.py` extracts relevant authentication events from the `auth.txt.gz`
  file and matches these events with those in the `redteam.txt.gz` to add ground truth
  labels.
- OpTC: `extract_optc.py` extracts FLOW START events from the raw gzipped JSON log
  files, drops irrelevant or duplicate flows, replaces IP addresses with hostnames
  when possible, and adds ground truth labels.
  It relies on `optc_known_addresses.json` for the IP address -> hostname mapping and
  `optc_redteam.csv` for labeling.

### Usage

Run `pip install -r requirements.txt` to install necessary dependencies.
Run `python extract_lanl.py -h` or `python extract_optc.py -h` to see the available
options.
