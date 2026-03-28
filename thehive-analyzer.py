#!/usr/bin/env python3
import json
import argparse

def parse_alert(data):
    d = json.loads(data)
    print(f"Alert: {d.get('title')}")
    print(f"Severity: {d.get('severity')}")
    for a in d.get('artifacts', []):
        print(f"  IOC: [{a.get('dataType')}] {a.get('data')}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("file")
    args = parser.parse_args()
    with open(args.file) as f:
        parse_alert(f.read())
