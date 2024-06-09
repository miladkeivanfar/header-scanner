## Security Header Checker
This Python script automates the process of checking security headers for a list of URLs. It helps identify potential security vulnerabilities on websites.


### Features
- Checks for a predefined set of common security headers:
- Content-Security-Policy
- Strict-Transport-Security
- Content-Type-Options
- X-Frame-Options
- X-Content-Type-Options
- Cache-Control
- Presents results in a clear tabular format with color-coded status indicators for easier readability.
- Provides options to:
- Specify a text file containing URLs to check.
- Ignore SSL verification errors (for testing purposes).

### Requirements
- Python 3
- requests library (`pip3 install requests`)
- urllib3 library (`pip3 install urllib3`)
- colorama library (optional, for colored output: `pip3 install colorama`)
- tabulate library (optional, for table formatting: `pip3 install tabulate`)
  
### Usage
1- Clone or download the repository.
2- Install required libraries:
```bash
pip3 install requests urllib3 colorama tabulate  # (optional for colored output and table formatting)
```
3- Create a text file (e.g., urls.txt) containing the URLs you want to check, with each URL on a separate line.
4- Run the script from the command line:
```bash
python3 sec-header_check.py -f urls.txt
```
- Replace urls.txt with the actual filename containing your URLs.
- Use the --ignore-ssl-errors flag to ignore SSL verification errors (not recommended for production):
```bash
python3 sec-header_check.py -f urls.txt --ignore-ssl-errors
```
### Example Output
The script will display the URLs, their status codes (color-coded for easy visual identification), and presence or absence of security headers in a table format:

![security header check example](https://github.com/khshathra-BH/sec-header-check/assets/129506375/e0db0324-b705-4088-9f93-30ea1aafd782)



- Match: Security header present
- WARNING: Security header missing (warning)

  
