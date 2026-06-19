import argparse
import datetime as dt
import gzip
import json
import math
import os

from collections import defaultdict

import pandas as pd

from joblib import Parallel, delayed




ORIGIN = dt.datetime.fromisoformat('1970-01-01T00:00:00.000-04:00')

def deduplicate_flows(flows):
    '''
    Removes duplicates from a list of flow events.
    Duplicates happen when system logs are available for both the source and
    destination of a flow: in that case, two events are recorded for the same
    flow, so we remove one of them.
    The input dictionary is modified in place and returned afterwards.

    Arguments
    ---------
    flows : dict
        Flow events stored as a (five-tuple) -> [(properties)] map.
        Keys are (source IP, destination IP, source port, destination port,
        protocol) tuples, and properties are (timestamp, direction, label)
        tuples.
        direction is a boolean; it is True if the flow is outbound.
        Values are lists of property tuples; each property tuple represents
        one FLOW START event.

    Returns
    -------
    flows : dict
        Input dictionary with duplicated events removed.

    '''

    for five_tuple, events in flows.items():
        # Compute the difference between the number of inbound and outbound
        # flows
        balance = sum(1 if direction else -1 for _, direction, _ in events)
        if balance == 0:
            # Exactly the same number of inbound and outbound flows -> logs
            # are available for both source and destination, so we can drop
            # all inbound (or, equivalently, outbound) flows
            flows[five_tuple] = [event for event in events if event[1]]
        elif math.fabs(balance) == len(events):
            # Only inbound or outbound flows -> logs are only available for
            # either the source or destination, so we keep them all
            continue
        else:
            # The only remaining tuples are edge cases where, for some reason,
            # there are inbound flows that do not match any outbound flow even
            # though logs are available for both the source and destination.
            # In this case, we keep only inbound flows
            flows[five_tuple] = [event for event in events if not event[1]]
    return flows

def extract_optc_dataset(base_dir, malicious_ids, addr_to_host, n_jobs=-1):
    '''
    Extracts FLOW START events from the OpTC dataset and preprocesses them.
    The input directory should be the ecar/ directory, with subdirectories
    benign/, short/ and evaluation/ containing the original GZIP-compressed
    JSON log files.

    Arguments
    ---------
    base_dir : str
        Path to the ecar/ directory containing the input log files.
    malicious_ids : set
        IDs of the malicious events.
    addr_to_host : dict
        IP address -> hostname map.
        Additional associations found during preprocessing will be added to
        this map.
    n_jobs : int, default=-1
        Number of parallel jobs to create (if -1, it is set to the number of
        available CPU cores).

    Returns
    -------
    flows : pd.DataFrame
        Dataframe containing the preprocessed flows.
        It has the following columns:
        - timestamp (int): time elapsed (in seconds) since first recorded event
        - src (str): source of the flow (hostname if available, otherwise
          IP address)
        - dst (str): destination of the flow (hostname if available, otherwise
          IP address)
        - src_port (int): source port
        - dst_port (int): destination port
        - proto (int): IP protocol number
        - label (int): 1 if malicious, otherwise 0

    '''

    # Read the raw data
    process_dir = lambda dirpath, filenames, malicious_ids: merge_flows_hosts([
        process_evts(os.path.join(dirpath, fname), malicious_ids)
        for fname in filenames
    ])
    res = Parallel(n_jobs=n_jobs)(
        delayed(process_dir)(dirpath, filenames, malicious_ids)
        for dirpath, _, filenames in os.walk(base_dir)
    )
    # Merge the results of the reading jobs
    flows, hosts = merge_flows_hosts(res)
    # Update IP address -> hostname mapping
    addr_to_host.update(hosts)
    # Remove duplicate events, i.e., flows recorded on both the source and
    # destination
    flows = deduplicate_flows(flows)
    # Replace IP addresses with hostnames where possible, offset timestamps
    # so they start at 0, and build sorted flow dataframe
    return make_flow_list(flows, addr_to_host)

def include_ip(addr):
    '''
    Indicates whether an IP address should be included in the dataset.
    Since we only consider internal flows, addresses outside the enterprise
    network are excluded.
    We also exclude broadcast and multicast addresses.

    Arguments
    ---------
    addr : str
        IP address.

    Returns
    -------
    is_included : bool
        True if the address is internal and not a broadcast or multicast
        address, False otherwise.

    '''

    if addr.startswith('10.') and not addr.endswith('.255'):
        return True
    if addr.startswith('142.') and addr != '142.20.59.255':
        return True
    if addr.startswith('fe80:'):
        return True
    return False

def make_flow_list(flows, addr_to_host):
    '''
    Turns a flow dictionary into a time-sorted dataframe where each row is one
    flow.
    Timestamps are stored as integers and shifted so that the first timestamp
    is 0.
    IP addresses are replaced with the corresponding hostnames when possible.

    Arguments
    ---------
    flows : dict
        Flow events stored as a (five-tuple) -> [(properties)] map.
        Keys are (source IP, destination IP, source port, destination port,
        protocol) tuples, and properties are (timestamp, direction, label)
        tuples.
        direction is a boolean; it is True if the flow is outbound.
        Values are lists of property tuples; each property tuple represents
        one FLOW START event.
    addr_to_host : dict
        IP address -> hostname map.

    Returns
    -------
    flows_df : pd.DataFrame
        Dataframe containing the time-sorted flows.
        It has the following columns:
        - timestamp (int): time elapsed (in seconds) since first recorded event
        - src (str): source of the flow (hostname if available, otherwise
          IP address)
        - dst (str): destination of the flow (hostname if available, otherwise
          IP address)
        - src_port (int): source port
        - dst_port (int): destination port
        - proto (int): IP protocol number
        - label (int): 1 if malicious, otherwise 0

    '''

    df = pd.DataFrame(
        [
            (ts, sip, dip, sport, dport, proto, lab)
            for (sip, dip, sport, dport, proto), events in flows.items()
            for ts, _, lab in events
        ],
        columns=[
            'timestamp', 'src', 'dst', 'src_port', 'dst_port',
            'proto', 'label'
        ]
    )
    # Set minimum timestamp to 0 and convert to int
    df['timestamp'] = (df['timestamp'] - df['timestamp'].min()).astype(int)
    # Replace IP addresses with hostnames when possible
    for col in ('src', 'dst'):
        df[col] = df[col].apply(lambda addr: addr_to_host.get(addr, addr))
    return df.sort_values('timestamp')

def make_timestamp(ts):
    '''
    Turns an ISO-formatted timestamp into its floating point representation
    (seconds elapsed since 1970-01-01 00:00:00).

    Arguments
    ---------
    ts : str
        ISO-formatted timestamp with timezone.

    Returns
    -------
    timestamp : float
        Timestamp converted to floating point representation.

    '''

    return (dt.datetime.fromisoformat(ts) - ORIGIN).total_seconds()

def merge_flows_hosts(tuples):
    '''
    Merges the flow dictionaries and address -> host mappings
    generated by reading the log files in the OpTC dataset.

    Arguments
    ---------
    tuples : list
        List of (flows, hosts) tuples, where flows is a dictionary of
        FLOW START events and hosts is an address -> host mapping.

    Returns
    -------
    flows : dict
        Merged dictionary of FLOW START events.
    hosts : dict
        Merged address -> host mapping.

    '''

    hosts = {}
    flows = defaultdict(list)
    for _flows, _hosts in tuples:
        for addr, host in _hosts.items():
            hosts[addr] = host
        for five_tuple, events in _flows.items():
            flows[five_tuple] += events
    return flows, hosts

def process_evts(filepath, malicious_ids):
    '''
    Extracts network flow events and an address -> host mapping from a
    raw log file (GZIP-compressed JSON format).

    Arguments
    ---------
    filepath : str
        Path to the log file.
    malicious_ids : set
        IDs of the malicious events.

    Returns
    -------
    flows : dict
        Flow events stored as a (five-tuple) -> [(properties)] map.
        Keys are (source IP, destination IP, source port, destination port,
        protocol) tuples, and properties are (timestamp, direction, label)
        tuples.
        direction is a boolean; it is True if the flow is outbound.
        Values are lists of property tuples; each property tuple represents
        one FLOW START event.
    hosts : dict
        Address -> host mapping.

    '''

    flows = defaultdict(list)
    hosts = {}
    with gzip.open(filepath, 'rt') as file:
        for line in file:
            if line[1:17] == '"action":"START"' and '"object":"FLOW"' in line:
                process_flow(line, flows, hosts, malicious_ids)
    return flows, hosts

def process_flow(line, flows, hosts, malicious_ids):
    '''
    Extracts a flow and address -> host correspondence from a FLOW START
    event in the OpTC dataset.

    Arguments
    ---------
    line : str
        Log line to process.
    flows : dict
        Flow events stored as a (five-tuple) -> [(properties)] map.
        Keys are (source IP, destination IP, source port, destination port,
        protocol) tuples, and properties are (timestamp, direction, label)
        tuples.
        direction is a boolean; it is True if the flow is outbound.
        Values are lists of property tuples; each property tuple represents
        one FLOW START event.
        The map is updated with the new event.
    hosts : dict
        Address -> host mapping to update.
    malicious_ids : set
        IDs of the malicious events.

    '''

    evt = json.loads(line)
    properties = evt['properties']
    (
        timestamp, evt_id, hostname,
        src_ip, dst_ip, src_port, dst_port, proto, is_outbound
    ) = (
        make_timestamp(evt['timestamp']), evt['id'], evt['hostname'],
        properties['src_ip'], properties['dest_ip'],
        int(properties['src_port']), int(properties['dest_port']),
        int(properties['l4protocol']), properties['direction'] == 'outbound'
    )
    if not include_ip(src_ip) or not include_ip(dst_ip):
        return
    five_tuple = (src_ip, dst_ip, src_port, dst_port, proto)
    label = int(evt_id in malicious_ids)
    flows[five_tuple].append((timestamp, is_outbound, label))
    if is_outbound:
        hosts[src_ip] = hostname
    else:
        hosts[dst_ip] = hostname


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'input_dir',
        help='Path to the ecar/ directory containing the input log files.'
    )
    parser.add_argument(
        '--redteam', '-r',
        default=None,
        help=(
            'Path to the file containing the labels for the malicious flow events. '
            'It must be a CSV file with at least two columns: `id` (event IDs) and '
            '`label` (Lateral movement or Other).'
        )
    )
    parser.add_argument(
        '--addresses', '-a',
        default=None,
        help=(
            'Path to the file containing the known IP address -> hostname mappings. '
            'It must be a JSON file with IP addresses as keys and hostnames as values.'
        )

    )
    parser.add_argument(
        '--output', '-o',
        default='optc.csv.gz',
        help='Path to the output file.'
    )
    parser.add_argument(
        '--lm-only', '-l',
        action='store_true',
        help=(
            'Use only events labeled as `Lateral movement` for evaluation. '
            'By default, all event IDs from the redteam file are labeled malicious.'
        )
    )
    parser.add_argument(
        '--jobs', '-j',
        type=int, default=-1,
        help=(
            'Number of parallel reading jobs (by default, it is equal to the number '
            'of available CPU cores.'
        )
    )
    args = parser.parse_args()

    if args.addresses is not None:
        with open(args.addresses) as f:
            addr_to_host = json.loads(f.read())
    else:
        addr_to_host = {}
    if args.redteam is None:
        malicious_ids = set()
    else:
        redteam = pd.read_csv(args.redteam)
        if args.lm_only:
            redteam = redteam[redteam['label'] == 'Lateral movement']
        malicious_ids = set(redteam['id'])

    flows = extract_optc_dataset(
        args.input_dir, malicious_ids, addr_to_host, n_jobs=args.jobs
    )
    flows.to_csv(args.output, index=False)