#!/usr/bin/env python3

import sys
import argparse
import time
import requests
import json

welcomeMsg = """
Welcome to the mass IP lookup! Please follow the configuration options, and submit a list, or file with IP addresses!

Options:
  --help              Show this help message
  --file, -f          Input file of IPs separated by line
  --sleep, -s         Time (in seconds) to sleep between queries
  --api               Your API key(s). Comma-separated if multiple (rotates automatically)
  --disposition, -d   Show disposition
  --country, -c       Show country
  --provider, -p      Show provider
"""

def parse_api_keys(api_arg):
    keys = [k.strip() for k in api_arg.split(",") if k.strip()]
    return keys if len(keys) > 1 else keys[0]

def parse_ips(raw_text):
    cleaned = raw_text.replace("\n", " ").replace(",", " ")
    cleaned = cleaned.replace('"', "").replace("'", "")
    return [ip.strip() for ip in cleaned.split() if ip.strip()]

def read_ips_from_file(path):
    with open(path, "r") as f:
        return parse_ips(f.read())

def lookup(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return {"error": r.text}
    return r.json()

def ask_yes_no(prompt, default=True):
    """
    Ask a yes/no question. Defaults to True (yes) unless user types 'n'.
    """
    ans = input(prompt).strip().lower()
    if ans in ("n", "no", "-n"):
        return False
    return True if ans else default

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-f", "--file", help="Input file of IPs separated by line")
    parser.add_argument("-s", "--sleep", type=int, help="Time to sleep between queries")
    parser.add_argument("--api", required=False, help="API key(s), comma separated")
    parser.add_argument("-d", "--disposition", action="store_true", help="Show disposition")
    parser.add_argument("-c", "--country", action="store_true", help="Show country")
    parser.add_argument("-p", "--provider", action="store_true", help="Show provider")
    parser.add_argument("-h", "--help", action="store_true", help="Show this help message")

    args = parser.parse_args()

    if args.help or (len(sys.argv) == 1 and not sys.stdin.isatty()):
        print(welcomeMsg)
        sys.exit(0)

    if len(sys.argv) == 1:
        print(welcomeMsg)
        readFromFile = input("Read from file? (y/n): ").lower() == "y"
        if readFromFile:
            filePath = input("Input file path exactly: ")
            IPs = read_ips_from_file(filePath)
        else:
            raw = input("Please enter IPs: ")
            IPs = parse_ips(raw)

        api_key = input("Enter your API key(s): ")
        api_keys = parse_api_keys(api_key)
        sleep_time = int(input("Sleep time between queries (seconds, default 0): ") or 0)
        disposition = ask_yes_no("Show disposition (Y/n)? ", default=True)
        country = ask_yes_no("Show country (Y/n)? ", default=True)
        provider = ask_yes_no("Show provider (Y/n)? ", default=True)

    else:
        if not args.api:
            print("Error: Need API key (--api)")
            sys.exit(1)

        api_keys = parse_api_keys(args.api)
        sleep_time = args.sleep or 0

        if args.file:
            IPs = read_ips_from_file(args.file)
        else:
            raw = input("Please enter IPs: ")
            IPs = parse_ips(raw)

        disposition, country, provider = args.disposition, args.country, args.provider

    if isinstance(api_keys, list):
        key_iter = iter(api_keys)
    else:
        key_iter = None

    for i, ip in enumerate(IPs):
        api_key = api_keys if isinstance(api_keys, str) else next(key_iter, api_keys[0])
        data = lookup(ip, api_key)

        if "error" in data:
            print(f"{ip}\tError: {data['error']}")
        else:
            attrs = data.get("data", {}).get("attributes", {})
            out = [ip]
            if disposition:
                out.append(f"disposition={attrs.get('last_analysis_stats')}")
            if country:
                out.append(f"country={attrs.get('country')}")
            if provider:
                out.append(f"asn={attrs.get('asn')}, isp={attrs.get('as_owner')}")
            print("\t".join(out))

        if sleep_time > 0 and i < len(IPs) - 1:
            time.sleep(sleep_time)

if __name__ == "__main__":
    main()
