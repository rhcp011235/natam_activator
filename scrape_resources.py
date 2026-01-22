#!/usr/bin/env python3
"""
Resource Scraper for Nattramn Payload
Extracts all URLs, file paths, credentials, and other resources from the script.

Usage: ./scrape_resources.py [script.sh] [-o output.txt]
"""

import re
import argparse
import sys
from collections import defaultdict

def extract_urls(content):
    """Extract all URLs"""
    # Match http/https URLs
    pattern = r'https?://[^\s"\'<>()]+[^\s"\'<>().,;:!?\]]'
    urls = re.findall(pattern, content)
    # Clean up trailing characters
    cleaned = []
    for url in urls:
        url = url.rstrip('\\').rstrip("'").rstrip('"')
        cleaned.append(url)
    return sorted(set(cleaned))

def extract_file_paths(content):
    """Extract file paths"""
    patterns = [
        r'~/[^\s"\'<>|&;]+',           # Home directory paths
        r'/tmp/[^\s"\'<>|&;]+',        # Temp paths
        r'/var/[^\s"\'<>|&;]+',        # Var paths
        r'/usr/[^\s"\'<>|&;]+',        # Usr paths
        r'/Library/[^\s"\'<>|&;]+',    # Library paths
        r'/Applications/[^\s"\'<>|&;]+', # Apps
        r'/private/[^\s"\'<>|&;]+',    # Private paths
        r'/etc/[^\s"\'<>|&;]+',        # Etc paths
        r'/bin/[^\s"\'<>|&;]+',        # Bin paths
    ]

    paths = []
    for pattern in patterns:
        matches = re.findall(pattern, content)
        paths.extend(matches)

    # Clean up
    cleaned = []
    for path in paths:
        path = path.rstrip('\\').rstrip("'").rstrip('"').rstrip(';').rstrip(')')
        if path and len(path) > 2:
            cleaned.append(path)

    return sorted(set(cleaned))

def extract_zip_info(content):
    """Extract zip files and their passwords"""
    zip_info = []

    # Find unzip commands with passwords
    pattern = r'unzip[^;|&\n]*-P\s+([^\s]+)[^;|&\n]*?([^\s]+\.zip)'
    matches = re.findall(pattern, content)
    for password, zipfile in matches:
        zip_info.append({'file': zipfile, 'password': password})

    # Also find password variables
    var_pattern = r"Unzp\d*\+='unzip[^']*-P\s+([^']+)'"
    var_matches = re.findall(var_pattern, content)

    # Find zip file references
    zip_files = re.findall(r'[^\s"\']+\.zip', content)
    zip_files = sorted(set(zip_files))

    return {
        'passwords': sorted(set(var_matches)),
        'zip_files': zip_files,
        'detailed': zip_info
    }

def extract_credentials(content):
    """Extract passwords, API keys, tokens"""
    creds = []

    # SSH passwords
    ssh_pass = re.findall(r'sshpass\s+-p\s+(\S+)', content)
    for p in ssh_pass:
        creds.append({'type': 'SSH Password', 'value': p})

    # Generic password patterns
    pass_patterns = [
        (r'-P\s+([^\s;|&]+)', 'Zip Password'),
        (r'password[=:]\s*["\']?([^"\';\s]+)', 'Password'),
        (r'passwd[=:]\s*["\']?([^"\';\s]+)', 'Password'),
        (r'api[_-]?key[=:]\s*["\']?([^"\';\s]+)', 'API Key'),
        (r'token[=:]\s*["\']?([^"\';\s]+)', 'Token'),
    ]

    for pattern, cred_type in pass_patterns:
        matches = re.findall(pattern, content, re.IGNORECASE)
        for m in matches:
            if len(m) > 2 and m not in ['alpine', '$password']:
                creds.append({'type': cred_type, 'value': m})

    return creds

def extract_domains(content):
    """Extract unique domains"""
    pattern = r'https?://([^/\s"\']+)'
    domains = re.findall(pattern, content)
    return sorted(set(domains))

def extract_api_endpoints(content):
    """Extract API endpoints and PHP files"""
    patterns = [
        r'https?://[^\s"\']+\.php[^\s"\']*',
        r'https?://[^\s"\']+/api/[^\s"\']*',
        r'https?://[^\s"\']+/v\d+/[^\s"\']*',
    ]

    endpoints = []
    for pattern in patterns:
        matches = re.findall(pattern, content)
        endpoints.extend(matches)

    return sorted(set(endpoints))

def extract_commands(content):
    """Extract interesting shell commands"""
    commands = {
        'curl_commands': [],
        'ssh_commands': [],
        'irecovery_commands': [],
        'other_tools': []
    }

    # Curl commands
    curl = re.findall(r'curl[^\n;|&]+', content)
    commands['curl_commands'] = sorted(set(curl))[:50]  # Limit

    # SSH/SCP commands
    ssh = re.findall(r'(?:ssh|scp)[^\n;]+', content)
    commands['ssh_commands'] = sorted(set(ssh))[:20]

    # irecovery commands
    irec = re.findall(r'\./irecovery[^\n;|&]+', content)
    commands['irecovery_commands'] = sorted(set(irec))[:30]

    # Other interesting tools
    tools = re.findall(r'\./(?:gaster|ipwnder|iproxy|img4tool|Kernel64Patcher|asr64)[^\n;|&]*', content)
    commands['other_tools'] = sorted(set(tools))[:30]

    return commands

def extract_device_ids(content):
    """Extract iOS device identifiers"""
    # Device IDs like iPhone10,6, iPad7,5, etc.
    devices = re.findall(r'(?:iPhone|iPad|iPod|AppleTV)\d+,\d+', content)
    return sorted(set(devices))

def extract_variables(content):
    """Extract important variable definitions"""
    vars_dict = {}

    # Variable assignments
    pattern = r"^([A-Za-z_][A-Za-z0-9_]*)\+?='([^']+)'"
    matches = re.findall(pattern, content, re.MULTILINE)

    for var, value in matches:
        if var not in vars_dict:
            vars_dict[var] = value

    return vars_dict

def main():
    parser = argparse.ArgumentParser(description='Scrape resources from shell script')
    parser.add_argument('script', nargs='?', default='nattramn_payload.sh',
                        help='Script to analyze (default: nattramn_payload.sh)')
    parser.add_argument('-o', '--output', default='scraped_resources.txt',
                        help='Output file (default: scraped_resources.txt)')
    parser.add_argument('-j', '--json', action='store_true',
                        help='Output as JSON')

    args = parser.parse_args()

    # Read script
    try:
        with open(args.script, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File '{args.script}' not found", file=sys.stderr)
        return 1

    print(f"[*] Analyzing {args.script} ({len(content)} bytes)...")

    # Extract everything
    data = {
        'urls': extract_urls(content),
        'domains': extract_domains(content),
        'api_endpoints': extract_api_endpoints(content),
        'file_paths': extract_file_paths(content),
        'zip_info': extract_zip_info(content),
        'credentials': extract_credentials(content),
        'device_ids': extract_device_ids(content),
        'commands': extract_commands(content),
        'variables': extract_variables(content),
    }

    if args.json:
        import json
        output = json.dumps(data, indent=2)
    else:
        # Format as text
        lines = []
        lines.append("=" * 80)
        lines.append("NATTRAMN PAYLOAD - SCRAPED RESOURCES")
        lines.append("=" * 80)
        lines.append("")

        # URLs
        lines.append("-" * 40)
        lines.append(f"URLS ({len(data['urls'])} found)")
        lines.append("-" * 40)
        for url in data['urls']:
            lines.append(f"  {url}")
        lines.append("")

        # Domains
        lines.append("-" * 40)
        lines.append(f"DOMAINS ({len(data['domains'])} found)")
        lines.append("-" * 40)
        for domain in data['domains']:
            lines.append(f"  {domain}")
        lines.append("")

        # API Endpoints
        lines.append("-" * 40)
        lines.append(f"API ENDPOINTS ({len(data['api_endpoints'])} found)")
        lines.append("-" * 40)
        for ep in data['api_endpoints']:
            lines.append(f"  {ep}")
        lines.append("")

        # ZIP Info
        lines.append("-" * 40)
        lines.append("ZIP PASSWORDS")
        lines.append("-" * 40)
        for pwd in data['zip_info']['passwords']:
            lines.append(f"  Password: {pwd}")
        lines.append("")
        lines.append(f"ZIP FILES ({len(data['zip_info']['zip_files'])} found)")
        for zf in data['zip_info']['zip_files'][:50]:
            lines.append(f"  {zf}")
        lines.append("")

        # Credentials
        lines.append("-" * 40)
        lines.append(f"CREDENTIALS ({len(data['credentials'])} found)")
        lines.append("-" * 40)
        seen = set()
        for cred in data['credentials']:
            key = f"{cred['type']}: {cred['value']}"
            if key not in seen:
                lines.append(f"  {key}")
                seen.add(key)
        lines.append("")

        # Device IDs
        lines.append("-" * 40)
        lines.append(f"iOS DEVICE IDENTIFIERS ({len(data['device_ids'])} found)")
        lines.append("-" * 40)
        for dev in data['device_ids']:
            lines.append(f"  {dev}")
        lines.append("")

        # File Paths
        lines.append("-" * 40)
        lines.append(f"FILE PATHS ({len(data['file_paths'])} found)")
        lines.append("-" * 40)
        for path in data['file_paths'][:100]:
            lines.append(f"  {path}")
        if len(data['file_paths']) > 100:
            lines.append(f"  ... and {len(data['file_paths']) - 100} more")
        lines.append("")

        # Important Variables
        lines.append("-" * 40)
        lines.append("IMPORTANT VARIABLES")
        lines.append("-" * 40)
        important_vars = ['Unzp', 'Unzp2', 'Unzp3', 'shps', 'shps1', 'shps2', 'shps3',
                         'irc', 'Msg0', 't1', 't2', 't3', 't4', 't5', 'fld']
        for var in important_vars:
            if var in data['variables']:
                lines.append(f"  {var} = '{data['variables'][var]}'")
        lines.append("")

        # Commands summary
        lines.append("-" * 40)
        lines.append("COMMANDS SUMMARY")
        lines.append("-" * 40)
        lines.append(f"  Curl commands: {len(data['commands']['curl_commands'])}")
        lines.append(f"  SSH commands: {len(data['commands']['ssh_commands'])}")
        lines.append(f"  iRecovery commands: {len(data['commands']['irecovery_commands'])}")
        lines.append(f"  Other tools: {len(data['commands']['other_tools'])}")
        lines.append("")

        # Sample irecovery commands
        lines.append("-" * 40)
        lines.append("SAMPLE IRECOVERY COMMANDS")
        lines.append("-" * 40)
        for cmd in data['commands']['irecovery_commands'][:15]:
            lines.append(f"  {cmd[:100]}")
        lines.append("")

        # Other tools
        lines.append("-" * 40)
        lines.append("OTHER EXPLOITATION TOOLS")
        lines.append("-" * 40)
        for cmd in data['commands']['other_tools'][:15]:
            lines.append(f"  {cmd[:100]}")

        lines.append("")
        lines.append("=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)

        output = "\n".join(lines)

    # Write output
    with open(args.output, 'w') as f:
        f.write(output)

    print(f"[+] Saved to {args.output}")
    print(f"    - URLs: {len(data['urls'])}")
    print(f"    - Domains: {len(data['domains'])}")
    print(f"    - File paths: {len(data['file_paths'])}")
    print(f"    - ZIP files: {len(data['zip_info']['zip_files'])}")
    print(f"    - Device IDs: {len(data['device_ids'])}")

    return 0

if __name__ == '__main__':
    sys.exit(main())
