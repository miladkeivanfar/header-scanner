## Header Scanner
This Python script automates the process of checking headers for a list of URLs. It helps identify potential security vulnerabilities on websites.


### Features
- Checks for a predefined set of common security headers:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
  - Cache-Control
- Checks for information common headers:
  - Server
  - X-Powered-By
  - X-AspNet-Version
  - X-AspNetMvc-Version
  - Access-Control-Allow-Origin (if CORS was enabled this response header exist) 
- Presents results in a clear tabular format with color-coded status indicators for easier readability.
- Provides options to:
- Specify a text file containing URLs to check.
- Ignore SSL verification errors (for testing purposes).
- Print failure URLs
- Add option for summery report
- Get subdomains in pipe (cat subdomains | python3 resolved_mapper.py )

### Requirements
- Python 3
  
### Usage
1- Clone or download the repository.

2- Install required libraries:
```bash
pip3 install -r requirements.txt
```
4- Run the script from the command line:
```bash
python3 header-scanner.py -f urls.txt
```
- Replace urls.txt with the actual filename containing your URLs.
- Use the --ignore-ssl-errors flag to ignore SSL verification errors (not recommended for production):
```bash
python3 header-scanner.py -f urls.txt --ignore-ssl-errors
```
## Optional arguments:
```bash
options:
  -h, --help               show this help message and exit
  -f URLS_FILE, --file     URLS_FILE
                           Path to a text file containing URLs, each url in a line (required)
  -r, --report             Show a summery report
  -k, --failure            Show failure URL
  -i, --ignore-ssl-errors  Ignore SSL verification errors
```

Colors:
- Match: Security header present
- WARNING: Security header missing (warning)
- Information: Information for finger print

  
