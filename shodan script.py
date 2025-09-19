#!/usr/bin/env python3
\"\"\"shodan_script.py
Simple student-style Shodan API script for class project.
Usage examples:
  # interactive: will prompt for API key and target
  python shodan_script.py
  # command-line: provide api key and target
  python shodan_script.py --api YOURKEY --mode ip --target 8.8.8.8 --output results.json

Dependencies:
  pip install shodan
\"\"\"

import os
import argparse
import json
from datetime import datetime

try:
    import shodan
except ImportError:
    print("Missing dependency: install with 'pip install shodan'")
    raise

def clean_shodan_host(host):
    \"\"\"Pick useful fields from a Shodan host result and normalize for JSON.\"\"\"
    cleaned = {}
    cleaned['ip_str'] = host.get('ip_str')
    cleaned['org'] = host.get('org')
    cleaned['isp'] = host.get('isp')
    cleaned['hostnames'] = host.get('hostnames', [])
    cleaned['ports'] = host.get('ports', [])
    cleaned['os'] = host.get('os')
    cleaned['location'] = {
        'city': host.get('city'),
        'region_code': host.get('region_code'),
        'country_name': host.get('country_name'),
        'latitude': host.get('latitude'),
        'longitude': host.get('longitude'),
    }
    # services: collect banner data per port
    services = []
    for item in host.get('data', []):
        svc = {
            'port': item.get('port'),
            'transport': item.get('transport'),
            'product': item.get('product'),
            'version': item.get('version'),
            'hostname': item.get('hostnames'),
            'banner': item.get('data'),
            'cpe': item.get('cpe'),
            'vulns': list(item.get('vulns', [])) if item.get('vulns') else []
        }
        services.append(svc)
    cleaned['services'] = services
    # vulnerabilities summary (flattened)
    vulns = set()
    for s in services:
        for v in s.get('vulns', []):
            vulns.add(v)
    cleaned['vulnerabilities'] = sorted(list(vulns))
    return cleaned

def run_shodan_api(api_key, mode, target):
    api = shodan.Shodan(api_key)
    if mode == 'ip':
        try:
            host = api.host(target)
            return {'type': 'host', 'queried': target, 'result': clean_shodan_host(host), '_queried_at': datetime.utcnow().isoformat() + 'Z'}
        except shodan.APIError as e:
            return {'error': str(e), 'queried': target}
    elif mode == 'query':
        try:
            res = api.search(target, limit=100)
            cleaned = []
            for match in res.get('matches', []):
                cleaned.append(clean_shodan_host(match))
            return {'type': 'search', 'query': target, 'total': res.get('total'), 'results': cleaned, '_queried_at': datetime.utcnow().isoformat() + 'Z'}
        except shodan.APIError as e:
            return {'error': str(e), 'query': target}
    else:
        return {'error': 'unknown mode', 'mode': mode}

def main(argv=None):
    parser = argparse.ArgumentParser(description='Simple Shodan script that returns cleaned JSON output.')
    parser.add_argument('--api', help='Shodan API key (or set SHODAN_API_KEY env var)')
    parser.add_argument('--mode', choices=['ip', 'query'], default='ip', help='ip = lookup host by IP; query = run a Shodan search query')
    parser.add_argument('--target', help='IP address (for mode=ip) or search query (for mode=query)')
    parser.add_argument('--output', help='Write JSON output to file instead of printing to stdout')
    parser.add_argument('--pretty', action='store_true', help='Pretty-print JSON')
    args = parser.parse_args(argv)

    api_key = args.api or os.getenv('SHODAN_API_KEY')
    if not api_key:
        api_key = input('Enter your Shodan API key: ').strip()

    mode = args.mode
    target = args.target
    if not target:
        if mode == 'ip':
            target = input('Enter IP address to lookup (ex: 8.8.8.8): ').strip()
        else:
            target = input('Enter Shodan search query (ex: "apache port:80"): ').strip()

    out = run_shodan_api(api_key, mode, target)

    json_text = json.dumps(out, indent=4 if args.pretty else None, ensure_ascii=False)

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(json_text)
            print(f"Wrote output to {args.output}")
        except Exception as e:
            print('Failed to write output file:', e)
            print(json_text)
    else:
        print(json_text)

if __name__ == '__main__':
    main()
