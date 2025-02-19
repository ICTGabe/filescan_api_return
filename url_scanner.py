import os
import sys
import requests
import time
import argparse
import json
import webbrowser

# Configuration
API_KEY = "API_KEY"
BASE_URL = "https://www.filescan.io/api"
WEB_URL = "https://www.filescan.io/uploads"
MAX_ATTEMPTS = 30
POLL_INTERVAL = 10

def scan_url(url, private=False, no_sharing=False):
    """Submit URL for scanning with privacy options and enhanced scan options."""
    headers = {"X-Api-Key": API_KEY}
    endpoint = f"{BASE_URL}/scan/url"
    
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    
    scan_options = {
        "osint": True,
        "extended_osint": True,
        "extracted_files_osint": True,
        "visualization": True,
        "files_download": True,
        "resolve_domains": True,
        "input_file_yara": True,
        "extracted_files_yara": True,
        "whois": True,
        "ips_meta": True,
        "images_ocr": True,
        "certificates": True,
        "url_analysis": True,
        "extract_strings": True,
        "ocr_qr": True,
        "phishing_detection": True,
        "rapid_mode": False,
        "early_termination": False
    }
    
    form_data = {
        "url": url,
        "filename": f"scan_{int(time.time())}.url",
        "tags": "enhanced-detailed-scan",
        "private": "true" if private else "false",
        "no_sharing": "true" if no_sharing else "false",
        "scan_options": json.dumps(scan_options)
    }
    
    try:
        response = requests.post(endpoint, headers=headers, data=form_data)
        response.raise_for_status()
        return response.json().get('flow_id')
    except Exception as e:
        print(f"Submission error: {str(e)}")
        return None

def poll_scan_results(flow_id):
    """Poll scan results with exponential backoff and display report URL."""
    headers = {"X-Api-Key": API_KEY}
    endpoint = f"{BASE_URL}/scan/{flow_id}/report"
    report_url = f"{WEB_URL}/{flow_id}"
    
    print(f"\nScan Report URL: {report_url}")
    print("Polling for results...")
    attempts = 0
    current_delay = POLL_INTERVAL
    
    while attempts < MAX_ATTEMPTS:
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()
            data = response.json()
            
            print(f"\nPoll attempt {attempts+1}/{MAX_ATTEMPTS}")
            status = "Finished" if data.get('allFinished') else "Processing"
            print(f"Status: {status}")
            
            if not data.get('allFinished'):
                for report in data.get('reports', {}).values():
                    progress = report.get('estimated_progress', 0)
                    queue = report.get('positionInQueue', 'N/A')
                    print(f"Progress: {progress*100:.1f}% | Queue Position: {queue}")
                    if report.get('additionalStepsRunning'):
                        print(f"Running: {', '.join(report['additionalStepsRunning'])}")
            
            if data.get('allFinished'):
                return data, report_url
                
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
    print(f"Manual check: {report_url}")
    return None, report_url

def process_final_results(data, report_url):
    """Display the detailed scan report overview."""
    print("\n" + "="*80)
    print("SCAN COMPLETE - DETAILED REPORT")
    print("="*80)
    print(f"Flow ID: {data.get('flowId', 'N/A')}")
    print(f"Final Verdict: {get_highest_verdict(data)}")
    print(f"Web Report URL: {report_url}")
    print(f"Scan Started: {data.get('scanStartedDate', 'N/A')}")
    print(f"Priority: {data.get('priority', 'N/A')}")
    print(f"Total Reports: {data.get('reportsAmount', 0)}")
    print("="*80)
    
    for rep_key, report in data.get('reports', {}).items():
        print("\n" + "="*60)
        print(f"REPORT ID: {rep_key}")
        print("="*60)
        
        file_info = report.get('file', {})
        print("FILE INFORMATION:")
        print(f"  File Name: {file_info.get('name', 'N/A')}")
        print(f"  File Hash: {file_info.get('hash', 'N/A')}")
        print(f"  File Type: {file_info.get('type', 'N/A')}")
        print(f"  File Size: {file_info.get('size', 'N/A')} bytes")
        
        verdict = report.get('finalVerdict', {})
        print("VERDICT:")
        print(f"  Result: {verdict.get('verdict', 'N/A')}")
        print(f"  Threat Level: {verdict.get('threatLevel', 'N/A')}")
        print(f"  Confidence: {verdict.get('confidence', 'N/A')}")
        
        print("PROCESSING INFO:")
        print(f"  Queue Position: {report.get('positionInQueue', 'N/A')}")
        print(f"  Overall State: {report.get('overallState', 'N/A')}")
        print(f"  Virus Total Rate: {report.get('vtRate', 'N/A')}")
        print(f"  Created Date: {report.get('created_date', 'N/A')}")
        print(f"  Estimated Time: {report.get('estimatedTime', 'N/A')} seconds")
        print(f"  Progress: {report.get('estimated_progress', 0)*100:.1f}%")
        ##################################SCAN CONFIG
        # print("\nSCAN CONFIGURATION:")
        # print(f"  Scan Profile: {report.get('scanProfile', 'N/A')}")
        # print(f"  Default Options Used: {report.get('defaultOptionsUsed', False)}")
        # if 'scanOptions' in report:
        #     print("\nSCAN OPTIONS:")
        #     for option, value in report['scanOptions'].items():
        #         status = "Yes" if value is True else "No"
        #         print(f"  {option}: {status}")
        
        print("PROCESSING STEPS:")
        print(f"  Files Download Finished: {report.get('filesDownloadFinished', False)}")
        print(f"  Additional Steps Done: {report.get('additionalStepsDone', False)}")
        if report.get('additionalStepsRunning'):
            print(f"  Running: {', '.join(report['additionalStepsRunning'])}")
        
        if report.get('osint'):
            print("\nOSINT RESULTS:")
            for key, value in report['osint'].items():
                print(f"  {key}: {value}")
        
        if report.get('network'):
            print("\nNETWORK INDICATORS:")
            network = report['network']
            if network.get('ips'):
                print("  IP Addresses:")
                for ip in network['ips']:
                    print(f"    - {ip}")
            if network.get('domains'):
                print("  Domains:")
                for domain in network['domains']:
                    print(f"    - {domain}")
            if network.get('urls'):
                print("  URLs:")
                for url in network['urls'][:5]:
                    print(f"    - {url}")
                if len(network['urls']) > 5:
                    print(f"    ... and {len(network['urls'])-5} more")
        
        if report.get('whois'):
            print("\nWHOIS DATA:")
            for key, value in report['whois'].items():
                if isinstance(value, list):
                    print(f"  {key}:")
                    for item in value[:5]:
                        print(f"    - {item}")
                    if len(value) > 5:
                        print(f"    ... and {len(value)-5} more")
                else:
                    print(f"  {key}: {value}")
    
    return data

def get_highest_verdict(data):
    """Determine the highest threat level with descriptive text."""
    max_level = 0
    for report in data.get('reports', {}).values():
        level = report.get('finalVerdict', {}).get('threatLevel', 0)
        if level > max_level:
            max_level = level
    
    if max_level == 0:
        return "BENIGN (Safe)"
    elif max_level < 0.3:
        return f"SUSPICIOUS - LOW (Level {max_level})"
    elif max_level < 0.7:
        return f"SUSPICIOUS - MEDIUM (Level {max_level})"
    elif max_level < 0.9:
        return f"SUSPICIOUS - HIGH (Level {max_level})"
    else:
        return f"MALICIOUS (Level {max_level})"

def extract_report_id_from_redirect(flow_id):
    """
    Extract the report ID by following the redirect from the scan URL.
    Filescan.IO redirects https://filescan.io/scan/[flow_id]/ to
    https://www.filescan.io/uploads/[flow_id]/reports/[report_id]/overview.
    """
    try:
        url = f"https://filescan.io/scan/{flow_id}/"
        response = requests.get(url, headers={"X-Api-Key": API_KEY}, allow_redirects=True)
        final_url = response.url  # Expected: .../uploads/<flow_id>/reports/<report_id>/overview
        parts = final_url.split("/")
        if "reports" in parts:
            index = parts.index("reports")
            if index + 1 < len(parts):
                report_id = parts[index + 1]
                print(f"Extracted report ID: {report_id}")
                return report_id
        return None
    except Exception as e:
        print(f"Error extracting report id from redirect: {e}")
        return None

def download_misp_report(report_id):
    """Download the MISP JSON report for the given report ID."""
    headers = {"X-Api-Key": API_KEY}
    misp_endpoint = f"{BASE_URL}/reports/{report_id}/download?format=misp"
    try:
        response = requests.get(misp_endpoint, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error downloading MISP report: {e}")
        return None

def print_misp_report_overview(misp_report):
    """Print a compact overview of key fields from the MISP report."""
    print("MISP Report Overview")
    if "Event" in misp_report:
        event = misp_report["Event"]
        print(f"Event ID: {event.get('id', 'N/A')}")
        print(f"Info: {event.get('info', 'N/A')}")
        print(f"Date: {event.get('date', 'N/A')}")
        print(f"Threat Level: {event.get('threat_level_id', 'N/A')}")
        attributes = event.get("Attribute") or event.get("Attributes")
        if attributes:
            print("Attributes:")
            for attr in attributes:
                print(f"  - {attr.get('type', 'N/A')}: {attr.get('value', 'N/A')}")
        else:
            print("No attributes found.")
    else:
        print("Unexpected MISP report format.")

def download_stix_report(report_id):
    """Download the STIX JSON report for the given report ID."""
    headers = {"X-Api-Key": API_KEY}
    stix_endpoint = f"{BASE_URL}/reports/{report_id}/download?format=stix"
    try:
        response = requests.get(stix_endpoint, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error downloading STIX report: {e}")
        return None

def print_stix_report_overview(stix_report):
    """Print a compact overview of key fields from the STIX report bundle."""
    if stix_report.get("type") == "bundle" and "objects" in stix_report:
        # First, print the report object (if available)
        for obj in stix_report["objects"]:
            if obj.get("type") == "report":
                report = obj
                print("\nSTIX Report Overview")
                print(f"Report ID: {report.get('id', 'N/A')}")
                print(f"Name: {report.get('name', 'N/A')}")
                print(f"Published: {report.get('published', 'N/A')}")
                rt = report.get("report_types", [])
                print(f"Report Types: {', '.join(rt) if rt else 'N/A'}")
                print(f"Created: {report.get('created', 'N/A')}")
                print(f"Modified: {report.get('modified', 'N/A')}")
                break
        # Now, print a compact overview of file objects
        print("\nSTIX Files:")
        for obj in stix_report["objects"]:
            if obj.get("type") == "file":
                hashes = obj.get("hashes", {})
                print(f"File ID: {obj.get('id', 'N/A')}")
                print(f"  Mime Type: {obj.get('mime_type', 'N/A')}")
                print(f"  SHA-1: {hashes.get('SHA-1', 'N/A')}")
                print(f"  SHA-256: {hashes.get('SHA-256', 'N/A')}")
                print(f"  MD5: {hashes.get('MD5', 'N/A')}")
        # Print URL objects
        print("\nSTIX URLs:")
        for obj in stix_report["objects"]:
            if obj.get("type") == "url":
                print(f"URL: {obj.get('value', 'N/A')}")
        # Print domain-name objects
        print("\nSTIX Domain Names:")
        for obj in stix_report["objects"]:
            if obj.get("type") == "domain-name":
                print(f"Domain: {obj.get('value', 'N/A')}")
        # Print IPv4 addresses
        print("\nSTIX IPv4 Addresses:")
        for obj in stix_report["objects"]:
            if obj.get("type") == "ipv4-addr":
                print(f"IPv4: {obj.get('value', 'N/A')}")
    else:
        print("Unexpected STIX report format.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enhanced FileScan.io URL Scanner")
    parser.add_argument("url", help="URL/Domain to scan")
    parser.add_argument("--private", action="store_true", help="Make scan private")
    parser.add_argument("--no-sharing", action="store_true", help="Disable result sharing")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--browser", action="store_true", help="Automatically open scan in browser")
    parser.add_argument("--flow-id", help="Extract data from existing flow ID")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--misp", action="store_true", help="Download and display MISP report overview")
    group.add_argument("--stix", action="store_true", help="Download and display STIX report overview")
    
    args = parser.parse_args()

    # Determine flow_id (either from a new scan or provided)
    if args.flow_id:
        flow_id = args.flow_id
        print("=== FileScan.io Detailed Report Extractor ===")
        print(f"Using existing Flow ID: {flow_id}")
        headers = {"X-Api-Key": API_KEY}
        endpoint = f"{BASE_URL}/scan/{flow_id}/report"
        report_url = f"{WEB_URL}/{flow_id}"
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()
            data = response.json()
            if args.json:
                print(json.dumps(data, indent=2))
            else:
                process_final_results(data, report_url)
        except Exception as e:
            print(f"Error retrieving scan data: {str(e)}")
    else:
        print("=== FileScan.io Enhanced URL Scanner ===")
        print(f"Target: {args.url}")
        # print(f"Private scan: {'Yes' if args.private else 'No'}")
        # print(f"No sharing: {'Yes' if args.no_sharing else 'No'}")
        flow_id = scan_url(args.url, private=args.private, no_sharing=args.no_sharing)
        if flow_id:
            print(f"Scan initiated successfully. Flow ID: {flow_id}")
            data, report_url = poll_scan_results(flow_id)
            if data:
                if args.json:
                    print("\n=== JSON OUTPUT ===")
                    print(json.dumps(data, indent=2))
                else:
                    process_final_results(data, report_url)
        else:
            print("Failed to initiate scan")
    
    # If either MISP or STIX is requested, extract the correct report ID and download the respective report.
    if args.misp or args.stix:
        if not args.flow_id and not flow_id:
            print("No valid flow ID available for threat report download.")
            sys.exit(1)
        current_flow = args.flow_id if args.flow_id else flow_id
        report_id = extract_report_id_from_redirect(current_flow)
        if not report_id:
            reports = data.get('reports', {}) if 'data' in locals() else {}
            if reports:
                report_id = list(reports.keys())[0]
        if report_id:
            if args.misp:
                misp_report = download_misp_report(report_id)
                if misp_report:
                    print_misp_report_overview(misp_report)
            elif args.stix:
                stix_report = download_stix_report(report_id)
                if stix_report:
                    print_stix_report_overview(stix_report)
        else:
            print("Failed to extract report ID for threat report download.")
