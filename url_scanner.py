import os
import sys
import requests
import time
import argparse
import json

# Configuration
API_KEY = "API_KEY"
BASE_URL = "https://www.filescan.io/api"
MAX_ATTEMPTS = 30
POLL_INTERVAL = 10

def scan_url(url, private=False, no_sharing=False):
    """Submit URL for scanning with privacy options"""
    headers = {"X-Api-Key": API_KEY}
    endpoint = f"{BASE_URL}/scan/url"
    
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    
    form_data = {
        "url": url,
        "filename": f"scan_{int(time.time())}.url",
        "tags": "automated-scan",
        "private": "true" if private else "false",
        "no_sharing": "true" if no_sharing else "false"
    }
    
    try:
        response = requests.post(endpoint, headers=headers, data=form_data)
        response.raise_for_status()
        return response.json().get('flow_id')
    except Exception as e:
        print(f"Submission error: {str(e)}")
        return None

def poll_scan_results(flow_id):
    """Poll scan results with exponential backoff"""
    headers = {"X-Api-Key": API_KEY}
    endpoint = f"{BASE_URL}/scan/{flow_id}/report"
    
    attempts = 0
    current_delay = POLL_INTERVAL
    
    while attempts < MAX_ATTEMPTS:
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            print(f"\nPoll attempt {attempts+1}/{MAX_ATTEMPTS}")
            print(f"Current status: {'All finished' if data['allFinished'] else 'Processing'}")
            
            if data['allFinished']:
                return process_final_results(data)
                
            current_delay = data.get('pollPause', current_delay)
            time.sleep(current_delay)
            attempts += 1
            
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error: {str(e)}")
            break
        except Exception as e:
            print(f"Polling error: {str(e)}")
            break
    
    print("\nMax polling attempts reached")
    print(f"Manual check: https://www.filescan.io/uploads/{flow_id}")
    return None

def process_final_results(data):
    """Process and display final scan results"""
    print("\n=== SCAN COMPLETE ===")
    print(f"Flow ID: {data['flowId']}")
    print(f"Final Verdict: {get_highest_verdict(data)}")
    
    for report_id, report in data['reports'].items():
        print(f"\n--- Report ID: {report_id} ---")
        print(f"File: {report['file']['name']}")
        print(f"Hash: {report['file']['hash']}")
        print(f"Type: {report['file'].get('type', 'N/A')}")
        print(f"Size: {report['file'].get('size', 'N/A')} bytes")
        print(f"Verdict: {report['finalVerdict']['verdict']}")
        print(f"Threat Level: {report['finalVerdict']['threatLevel']}")
        print(f"Confidence: {report['finalVerdict'].get('confidence', 'N/A')}")
        
        # Network indicators
        if 'network' in report:
            print("\nNetwork Indicators:")
            print(f"IPs: {', '.join(report['network'].get('ips', []))}")
            print(f"Domains: {', '.join(report['network'].get('domains', []))}")
            print(f"URLs: {', '.join(report['network'].get('urls', []))}")
        
        # YARA matches
        if 'yara' in report and report['yara']:
            print("\nYARA Matches:")
            for yara_match in report['yara']:
                print(f"- Rule: {yara_match.get('rule', 'N/A')}")
                print(f"  Description: {yara_match.get('description', 'N/A')}")
        
        # Sandbox analysis
        if 'sandbox' in report:
            print("\nSandbox Analysis:")
            print(f"Score: {report['sandbox'].get('score', 'N/A')}")
            print(f"Verdict: {report['sandbox'].get('verdict', 'N/A')}")
        
        # Additional metadata
        print("\nAdditional Metadata:")
        print(f"Created Date: {report.get('created_date', 'N/A')}")
        print(f"Estimated Progress: {report.get('estimated_progress', 'N/A')}")
    
    return data

def get_highest_verdict(data):
    """Determine the highest threat level"""
    max_level = 0
    for report in data['reports'].values():
        level = report['finalVerdict']['threatLevel']
        if level > max_level:
            max_level = level
    return f"THREAT_LEVEL_{max_level}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FileScan.io URL Scanner")
    parser.add_argument("url", help="URL/Domain to scan")
    parser.add_argument("--private", action="store_true", help="Make scan private")
    parser.add_argument("--no-sharing", action="store_true", help="Disable result sharing")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    
    args = parser.parse_args()

    if flow_id := scan_url(args.url, private=args.private, no_sharing=args.no_sharing):
        print(f"Scan initiated successfully. Flow ID: {flow_id}")
        results = poll_scan_results(flow_id)
        if results and args.json:
            print(json.dumps(results, indent=2))
    else:
        print("Failed to initiate scan")
