# filescan_api_return
A python script which uses the filescan API function for scanning domains, and processing via API

Required install: 
`pip install filescan_cli`




To scan a URL with privacy protections for confidential information:   
`python3 url_scanner.py example.com --private --no-sharing`   
To scan with custom tags and comments:   
`python3 url_scanner.py example.com --private --tags "confidential,important" --comment "Sensitive data scan"`   
To get notified when the scan completes (if the API supports it):   
`python3 url_scanner.py example.com --private --notify`    
To scan with json output:  
`python3 url_scanner.py example.com --private --no-sharing --json`
