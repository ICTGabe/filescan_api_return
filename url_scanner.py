import os
import sys
import requests
import json
import uuid
import argparse
import time

# Configuration
API_KEY = "API_KEY"
BASE_URL = "https://www.filescan.io/api"
POLLING_MAX_ATTEMPTS = 40  # Increased from 30
POLLING_INITIAL_DELAY = 10  # Reduced from 15
POLLING_MAX_DELAY = 300  # Increased from 120

def scan_url(domain, private=False, additional_args=None):
    print("\n=== Starting URL Scan ===")
    if not domain.startswith(("http://", "https://")):
        url = f"http://{domain}"
        print(f"Added http:// prefix to domain. URL is now: {url}")
    else:
        url = domain
    
    headers = {
        "X-Api-Key": API_KEY,
        "Accept": "application/json"
    }
    
    domain_name = domain.split('/')[0].replace('.', '_')
    filename = f"{domain_name}_{str(uuid.uuid4())[:8]}.url"
    
    form_data = {
        "url": url,
        "filename": filename,
        "comment": "Automated scan",
        "tags": "automated,routine",
        "private": "true" if private else "false"
    }
    
    if additional_args:
        form_data.update(additional_args)

    try:
        response = requests.post(
            f"{BASE_URL}/scan/url",
            headers=headers,
            data=form_data
        )
        
        if response.status_code == 200:
            result = response.json()
            flow_id = result.get("flow_id")
            
            if flow_id:
                print(f"\nScan initiated successfully. Flow ID: {flow_id}")
                print(f"Scan overview: https://www.filescan.io/uploads/{flow_id}")
                return flow_id
            else:
                print("Error: No flow_id in response")
        else:
            print(f"API Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Scan submission failed: {str(e)}")
    
    return None

def poll_for_results(flow_id):
    headers = {"X-Api-Key": API_KEY}
    status_url = f"{BASE_URL}/uploads/{flow_id}"
    report_id = None
    
    print(f"\n=== Polling Scan Status ===\n{status_url}")
    
    for attempt in range(POLLING_MAX_ATTEMPTS):
        try:
            response = requests.get(status_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                state = data.get("state", "UNKNOWN")
                progress = data.get("progress", 0)
                
                print(f"Attempt {attempt+1}: {state} ({progress}%)")
                
                if state == "DONE":
                    reports = data.get("reports", [])
                    if reports:
                        report_id = reports[0].get("id")
                        break
                    else:
                        print("No reports available yet")
                elif state == "FAILED":
                    print(f"Scan failed: {data.get('error', 'Unknown error')}")
                    return
                
            elif response.status_code == 404:
                print("Scan pending...")
            
            # Dynamic backoff calculation
            delay = min(POLLING_INITIAL_DELAY * (2 ** attempt), POLLING_MAX_DELAY)
            time.sleep(delay)
            
        except Exception as e:
            print(f"Polling error: {str(e)}")
            break

    if report_id:
        get_report(flow_id, report_id)
    else:
        print("\n=== Maximum Polling Attempts Reached ===")
        print(f"Manual check: https://www.filescan.io/uploads/{flow_id}")

def get_report(flow_id, report_id):
    try:
        report_url = f"{BASE_URL}/uploads/{flow_id}/reports/{report_id}"
        response = requests.get(report_url, headers={"X-Api-Key": API_KEY})
        
        if response.status_code == 200:
            report = response.json()
            print("\n=== Scan Report ===")
            print(f"Final Verdict: {report.get('verdict', 'Unknown')}")
            print(f"Threat Score: {report.get('score', 'N/A')}")
            
            # Process network indicators
            if "network" in report:
                print("\nNetwork Indicators:")
                print(f"IPs: {', '.join(report['network'].get('ips', []))}")
                print(f"Domains: {', '.join(report['network'].get('domains', []))}")
            
            print(f"\nFull Report: https://www.filescan.io/uploads/{flow_id}/reports/{report_id}/overview")
        else:
            print(f"Failed to retrieve report: {response.status_code}")
            
    except Exception as e:
        print(f"Report retrieval failed: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FileScan.io URL Scanner")
    parser.add_argument("url", help="URL/Domain to scan")
    parser.add_argument("--private", action="store_true", help="Private scan")
    parser.add_argument("--no-sharing", action="store_true", help="Disable sharing")
    args = parser.parse_args()

    additional_args = {}
    if args.no_sharing:
        additional_args["no_sharing"] = "true"

    flow_id = scan_url(args.url, private=args.private, additional_args=additional_args)
    
    if flow_id:
        poll_for_results(flow_id)
