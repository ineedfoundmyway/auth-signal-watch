import argparse
from collections import defaultdict, deque
from datetime import datetime
import ipaddress
import json
from pathlib import Path

def parse(line):
    row = json.loads(line)
    stamp = datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('timestamp requires timezone')
    ipaddress.ip_address(row['source_ip'])
    if row['outcome'] not in {'failure', 'success'}:
        raise ValueError('unknown outcome')
    if not isinstance(row['user'], str) or not row['user']:
        raise ValueError('user required')
    return stamp, row

def detect(lines, threshold=3, window=60):
    if threshold < 1 or window < 1:
        raise ValueError('positive threshold and window required')
    parsed = [parse(line) for line in lines if line.strip()]
    parsed.sort(key=lambda item: item[0])
    history = defaultdict(deque)
    alerts = []
    for stamp, row in parsed:
        key = (row['source_ip'], row['user'])
        failures = history[key]
        while failures and (stamp - failures[0]).total_seconds() > window:
            failures.popleft()
        if row['outcome'] == 'failure':
            failures.append(stamp)
            if len(failures) == threshold:
                alerts.append({'rule': 'failure-burst', 'source_ip': key[0], 'user': key[1], 'failures': len(failures), 'timestamp': row['timestamp']})
        else:
            if len(failures) >= threshold:
                alerts.append({'rule': 'success-after-failures', 'source_ip': key[0], 'user': key[1], 'failures': len(failures), 'timestamp': row['timestamp']})
            failures.clear()
    return alerts

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('file', type=Path)
    parser.add_argument('--threshold', type=int, default=3)
    parser.add_argument('--window', type=int, default=60)
    args = parser.parse_args()
    try:
        print(json.dumps(detect(args.file.read_text().splitlines(), args.threshold, args.window), indent=2))
    except (ValueError, KeyError, OSError) as error:
        parser.exit(2, f'Invalid input: {error}\n')
