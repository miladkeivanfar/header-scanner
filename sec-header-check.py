import argparse
import requests
import urllib3
from colorama import Fore, Style
from tabulate import tabulate
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

class config:
    all_headers = ["Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Cache-Control",
            "Server",
            "X-Powered-By",
            "X-AspNet-Version",
            "X-AspNetMvc-Version",
            "Access-Control-Allow-Origin"]

    security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Cache-Control"]

    information_headers = ["Server","X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version","Access-Control-Allow-Origin"]

def check_security_headers(urls, ignore_ssl_errors):

    for url in urls:
        try:
            response = requests.get(url, verify=ignore_ssl_errors, headers={"Origin":url})  
        except Exception as e:
            exit(f"[Error] Failure {url}: {e}")

        headers = response.headers
        status_code = response.status_code

        if status_code in range (200, 299):
            print(f"\n{Fore.CYAN + url + Style.RESET_ALL}" , " ", Fore.GREEN + str(status_code) + Style.RESET_ALL)

        elif status_code in range (300, 399):
            print(f"\n{Fore.CYAN + url + Style.RESET_ALL}" , " ", Fore.BLUE + str(status_code) + Style.RESET_ALL)

        elif status_code in range (400, 499):
            print(f"\n{Fore.CYAN + url + Style.RESET_ALL}" , " ", Fore.RED + str(status_code) + Style.RESET_ALL)

        elif status_code in range (500, 599):
            print(f"\n{Fore.CYAN + url + Style.RESET_ALL}" , " ", Fore.RED + str(status_code) + Style.RESET_ALL)

        # Check for each security header
        table = []
        for header_name in config.all_headers:
            if header_name in headers:

                if header_name in config.security_headers:
                    status = Fore.GREEN + "Match" + Style.RESET_ALL 
                    table.append([status, header_name, headers[header_name]])

                if header_name in config.information_headers:
                    status = Fore.BLUE + "Information" + Style.RESET_ALL
                    table.append([status, header_name, headers[header_name]])

            elif header_name in config.security_headers: 
                    status = Fore.YELLOW + "Warning" + Style.RESET_ALL  
                    table.append([status, header_name, "-"])

        print(tabulate(table, headers=["Status", "Header", "Value"]))


def read_urls_from_file(filename):

    if filename is None:
        print("Error: No file path provided.")
        return []  # Return an empty list if no filename is given

    try:
        with open(filename, "r") as file:
            urls = [line.strip() for line in file.readlines()]
            return urls
    except FileNotFoundError:
        print(f"Error: File not found: {filename}")
        return []
    except PermissionError:
        print(f"Error: Permission denied to read file: {filename}")
        return []

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Check security headers for URLs")
    parser.add_argument("-f", "--file", dest="urls_file", required=True,
                        help="Path to a text file containing URLs, each url in a line (required)")
    parser.add_argument("--ignore-ssl-errors", action="store_false", default=True,
                        help="Ignore SSL verification errors ")
    args = parser.parse_args()

    # Read URLs from the file
    urls = read_urls_from_file(args.urls_file)

    # Check security headers if URLs were read successfully
    if urls:
        check_security_headers(urls, ignore_ssl_errors=args.ignore_ssl_errors)
