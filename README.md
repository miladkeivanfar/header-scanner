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

### Requirements
- Python 3
  
### Usage
1- Clone or download the repository.
2- Install required libraries:
```bash
pip3 install -r requirements.txt
```
3- Create a text file (e.g., urls.txt) containing the URLs you want to check, with each URL on a separate line.
4- Run the script from the command line:
```bash
python3 header-scanner.py -f urls.txt
```
- Replace urls.txt with the actual filename containing your URLs.
- Use the --ignore-ssl-errors flag to ignore SSL verification errors (not recommended for production):
```bash
python3 header-scanner.py -f urls.txt --ignore-ssl-errors
```
### Example Output
The script will display the URLs, their status codes (color-coded for easy visual identification), and presence or absence of security headers in a table format:

![security header check example](https://github.com/khshathra-BH/sec-header-check/assets/129506375/e0db0324-b705-4088-9f93-30ea1aafd782)



- Match: Security header present
- WARNING: Security header missing (warning)

  
