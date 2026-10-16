#!/usr/bin/env python3
"""Verify public result integrity and recompute summaries without network access."""
from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import ipaddress
import itertools
import json
import math
from pathlib import Path
import re
import statistics

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / 'docs' / 'experiments'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load(name, result_root=RESULTS):
    return json.loads((result_root / 'data' / name).read_text())


def quantile(values, fraction):
    values = sorted(values)
    if not values:
        return None
    offset = (len(values) - 1) * fraction
    lo, hi = math.floor(offset), math.ceil(offset)
    return values[lo] + (values[hi] - values[lo]) * (offset - lo)


def summarize_transfers(rows):
    """All attempted TX enters cost; only verified bodies enter its denominator."""
    attempted = [r for r in rows if r['file_attempted']]
    verified = [r for r in attempted if r['success']]
    denominator = sum(r['file_bytes'] for r in verified)
    tx = sum(r['gateway_tx_bytes'] for r in attempted)
    return {'attempts': len(attempted), 'successful': len(verified),
            'verified_body_bytes': denominator, 'gateway_tx_including_failures': tx,
            'failed_transfer_tx_bytes': sum(r['gateway_tx_bytes'] for r in attempted if not r['success']),
            'gateway_tx_per_verified_body': tx / denominator if denominator else None,
            'setup_records': len(rows) - len(attempted),
            'setup_tx_bytes': sum(r['gateway_tx_bytes'] for r in rows if not r['file_attempted'])}


def summarize_requests(rows):
    """A paired session requires both verified directions, never one fast request."""
    sessions = defaultdict(dict)
    for row in rows:
        key = (row['case_id'], row['session'])
        require(row['direction'] not in sessions[key], 'duplicate session direction')
        sessions[key][row['direction']] = row
    both = lambda pair: (set(pair) == {'download', 'upload'} and
                         all(x['ok'] for x in pair.values()))
    result = {'requests': len(rows), 'verified_requests': sum(r['ok'] for r in rows),
              'sessions': len(sessions),
              'both_verified_sessions': sum(both(p) for p in sessions.values()),
              'both_ge20_sessions': sum(both(p) and all(x['mbps'] >= 20 for x in p.values())
                                        for p in sessions.values())}
    for direction in ('download', 'upload'):
        selected = [r for r in rows if r['direction'] == direction]
        valid = [r for r in selected if r['ok']]
        body = sum(r['body'] for r in valid)
        tx = sum(r['gateway_tx_bytes'] for r in selected)
        result[direction] = {'attempts': len(selected), 'verified': len(valid),
            'verified_body_bytes': body, 'gateway_tx_including_failures': tx,
            'gateway_tx_per_verified_body': tx / body if body else None,
            'ge20': sum(r['mbps'] >= 20 for r in valid),
            'median_mbps': statistics.median(r['mbps'] for r in valid) if valid else None,
            'p10_mbps': quantile([r['mbps'] for r in valid], .1)}
    return result


def privacy_findings(text):
    """Report categories only; never echo a matched address or credential."""
    findings = set()
    for match in re.finditer(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])', text):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        allowed = (address.is_loopback or address.is_unspecified or any(
            address in ipaddress.ip_network(net)
            for net in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')))
        if not allowed:
            findings.add('non-documentation IP address')
    # IPv6 examples must also use the documentation range or loopback.
    for match in re.finditer(r'(?<![\w:])(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9]{0,4}(?![\w:])', text):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        if not (address.is_loopback or address.is_unspecified or
                address in ipaddress.ip_network('2001:db8::/32')):
            findings.add('non-documentation IPv6 address')
    rules = {
        'personal home path': r'/(?:Users|home)/[A-Za-z0-9_.-]+',
        'email or credential URL': r'[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|://[^\s/]+@',
        'private key': r'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----',
        'exact operational timestamp': r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',
        'cloud resource identifier': r'\b(?:eip|ins|vpc|subnet)-[a-z0-9]{6,}\b',
        'machine identity': r'\b(?:VM-\d+-\d+-[\w-]+|DESKTOP-[\w-]+|LAPTOP-[\w-]+)\b',
    }
    for category, pattern in rules.items():
        if re.search(pattern, text):
            findings.add(category)
    # Public results use local references; an endpoint must never be slipped in.
    if re.search(r'https?://', text):
        findings.add('external URL requires explicit privacy review')
    domain_pattern = r'(?<![\w.-])(?:[A-Za-z0-9-]+\.)+(?:com|cn|net|org|io|cloud|tech|xyz|site|online|top|cc|local|internal|lan)\b'
    for match in re.finditer(domain_pattern, text, re.I):
        domain = match.group().lower()
        if not any(domain == d or domain.endswith('.' + d)
                   for d in ('example.com', 'example.net', 'example.org')):
            findings.add('non-example domain')
    return sorted(findings)


def verify(result_root=RESULTS):
    manifest = json.loads((result_root / 'manifest.json').read_text())
    actual = {str(p.relative_to(result_root)) for p in result_root.rglob('*')
              if p.is_file() and p.name != 'manifest.json'}
    require(actual == set(manifest['files']), 'manifest file set differs')
    for name, expected in manifest['files'].items():
        raw = (result_root / name).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == expected, f'{name}: digest differs')
        findings = privacy_findings(raw.decode('utf-8'))
        require(not findings, f'{name}: privacy review failed: {findings}')

    clients = load('client-transports.json', result_root)['samples']
    expected = {'hy2-client': 41, 'hy2-default': 5, 'trojan-client': 8, 'trojan-transit': 6}
    require({f:sum(r['family'] == f for r in clients) for f in expected} == expected,
            'client experiment coverage differs')
    for row in clients:
        if row['success']:
            require(math.isclose(row['Mbps'], row['file_bytes'] * 8 / row['duration_s'] / 1e6,
                                 rel_tol=1e-9), 'client throughput arithmetic differs')
            wire = row.get('sender_udp_l3_tx', row.get('sender_tcp_l3_tx'))
            require(math.isclose(row['wire_per_verified_file'], wire / row['file_bytes'], rel_tol=1e-9),
                    'client wire factor arithmetic differs')
        else:
            require(row['Mbps'] is None and row['wire_per_verified_file'] is None,
                    'incomplete file represented as verified throughput')

    chain = load('full-chain.json', result_root)['records']
    attempted = [r for r in chain if r['file_attempted']]
    keys = [(r['client'], r['gateway'], r['candidate'], r['direction'], r['block']) for r in attempted]
    expected_keys = set(itertools.product(('client-A','client-B','client-C'),
        ('gateway-B','gateway-C'), ('TT','TTc','TH','HT','HH'), ('download','upload'), (1,2)))
    require(len(keys) == len(set(keys)) == 120 and set(keys) == expected_keys,
            'full-chain matrix is duplicated or incomplete')
    chain_summary = {mode:summarize_transfers([r for r in chain if r['candidate'] == mode])
                     for mode in ('TT','TTc','TH','HT','HH')}
    for row in attempted:
        require(row['cost_complete'], 'full-chain cost is missing')
        if row['success']:
            require(math.isclose(row['Mbps'], row['file_bytes'] * 8 / row['duration_s'] / 1e6, rel_tol=1e-9),
                    'full-chain throughput differs')
            require(math.isclose(row['gateway_tx_factor'], row['gateway_tx_bytes'] / row['file_bytes'], rel_tol=1e-9),
                    'full-chain cost factor differs')

    controller = load('adaptive-controller.json', result_root)
    requests = controller['requests']
    require(len(requests) == 1232 and sum(r['primary'] for r in requests) == 948,
            'controller cohort coverage differs')
    require(len({r['request_id'] for r in requests}) == len(requests), 'duplicate request identity')
    for row in requests:
        if row['ok']:
            require(row['digest_match'], 'verified request has a digest mismatch')
            require(math.isclose(row['mbps'], row['body'] * 8 / row['duration_s'] / 1e6, rel_tol=1e-9),
                    'controller throughput differs')
    primary = [r for r in requests if r['primary']]
    controller_summary = {}
    for mode in ('tcp','split','controller'):
        summary = summarize_requests([r for r in primary if r['candidate'] == mode])
        source = controller['source_primary_aggregates']['combined/'+mode]
        require(summary['sessions'] == source['sessions']['attempts'] and
                summary['both_ge20_sessions'] == source['sessions']['both_ge20'],
                'controller paired-session summary differs from source aggregate')
        for direction in ('download','upload'):
            a,b=summary[direction],source[direction]
            require(a['verified'] == b['verified'] and a['ge20'] == b['ge20'],
                    'controller direction counts differ')
            require(math.isclose(a['gateway_tx_per_verified_body'], b['tx_per_verified_body'], rel_tol=1e-9),
                    'controller failed-cost denominator differs')
        controller_summary[mode]=summary

    baseline=load('transport-baselines.json', result_root)
    require(len(baseline['cases']) == 76 and len(baseline['phases']) == 267, 'baseline coverage differs')
    require(sum(r['gateway_tx'] for r in baseline['cases']) == baseline['gateway_tx_case_windows_bytes'],
            'baseline case cost differs')
    require(sum(r['gateway_tx'] for r in baseline['phases']) == baseline['gateway_tx_phase_windows_bytes'],
            'baseline phase cost differs')

    probes=load('path-diagnostics.json', result_root)['probes']
    require(len(probes) == 36, 'packet probe coverage differs')
    probe_summary={}
    for sender in ('gateway-B','origin'):
        rows=[r for r in probes if r['sender'] == sender]
        sent=sum(r['sent'] for r in rows);missing=sum(r['missing'] for r in rows)
        require(all(r['sent'] - r['receiver_nic_unique'] == r['missing'] for r in rows),
                'packet missing count does not reconcile')
        require(all(r['receiver_nic_unique'] == r['application_unique'] for r in rows),
                'local receive gap present')
        probe_summary[sender]={'sent':sent,'missing':missing,'missing_fraction':missing/sent}
    coded=load('coded-transport.json', result_root)
    require(sum(x['cases'] for x in coded['local']) == 56, 'local coded matrix coverage differs')
    require(sum(x['cases'] for x in coded['network']) == 20, 'network coded matrix coverage differs')
    require(sum(x['cases'] for b in coded['followup'] for x in b['groups']) == 24,
            'coded followup coverage differs')

    observation=load('metering-observation.json', result_root)
    for n in observation['nodes']:
        p=n['payload']['total_bytes']
        require(n['payload']['upload_bytes'] + n['payload']['download_bytes'] == p,
                'payload total differs')
        if p:
            require(math.isclose(n['ratios']['tx_per_payload'],n['device']['tx']/p,rel_tol=1e-9),
                    'device-to-payload comparison differs')
        else:
            require(n['ratios']['tx_per_payload'] is None, 'zero-payload amplification must be undefined')
    return {'schema_version':1,'full_chain':chain_summary,'controller_primary':controller_summary,
            'controller_all':summarize_requests(requests),'packet_probes':probe_summary,
            'client_families':{f:{'attempts':n,'successful':sum(r['success'] for r in clients if r['family']==f)}
                               for f,n in expected.items()}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write-summary',action='store_true',help='write the recomputed public summary')
    args=parser.parse_args()
    try:
        summary=verify()
        target=RESULTS/'summary.json'
        if args.write_summary:
            target.write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
        else:
            require(json.loads(target.read_text()) == summary, 'saved summary differs from independent recomputation')
    except (ValueError,OSError,KeyError,TypeError) as exc:
        parser.exit(1,f'experiment results: FAILED: {exc}\n')
    print('experiment results: OK (file hashes, privacy rules, denominators, failures, coverage and summary)')


if __name__ == '__main__':
    main()
