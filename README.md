# filescan_api_return
A python script which uses the filescan API function for scanning domains, and processing via API.  
Available output, MISP JSON, STIX JSON or plain text  

Reference link: https://github.com/filescanio/fsio-cli


Required install: 
`pip install filescan_cli`  
Note: on windows, the "windows-curses" dependency might need to be satisfied:  
`pip install windows-curses`




To scan a URL with privacy protections for confidential information:   
`python3 url_scanner.py example.com --private --no-sharing`   
To scan with custom tags and comments:   
`python3 url_scanner.py example.com --private --tags "confidential,important" --comment "Sensitive data scan"`   
To get notified when the scan completes (if the API supports it):    
`python3 url_scanner.py example.com --private --notify`       
To scan with json (STIX/MISP) output:     
`python3 url_scanner.py example.com --misp --private --no-sharing`  
`python3 url_scanner.py example.com --stix --private --no-sharing`  
