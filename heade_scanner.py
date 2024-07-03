#!/usr/bin/python3
import argparse
import requests
import urllib3
import sys
import time
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

    information_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                           "Access-Control-Allow-Origin"]


def convert_duration(duration):
    # Convert the duration to seconds
    total_seconds = duration

    # Calculate hours, minutes, and seconds
    hours = int(total_seconds // 3600)
    minutes = int((total_seconds % 3600) // 60)
    seconds = int(total_seconds % 60)

    # Format the duration
    if hours > 0:
        formatted_duration = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    elif minutes > 0:
        formatted_duration = f"{minutes:02d}:{seconds:02d}"
    else:
        formatted_duration = f"00:00:{seconds:02d}"

    return formatted_duration


def report(all_url, duration_process=None, failure_count=None):
    print("\n")
    print(Fore.GREEN + 'Summery Report:\n' + Style.RESET_ALL)

    table = [["Duration", duration_process, "Duration of process"], ["", "", ""],
             ["All URLs", all_url, "Number of URL in input file"]
        , [Fore.RED +"Failure URL"+Style.RESET_ALL, failure_count, "Number of Failure URL"]]

    print(tabulate(table, headers=["Name", "Quantity", "Description"], tablefmt="github"))


def check_security_headers(urls, ignore_ssl_errors):
    failure_url = []

    failure_count = 0

    for url in urls:
        try:
            if url.startswith("http"):
                response = requests.get(url, verify=ignore_ssl_errors, headers={"Origin": url})
            else:
                print(f"Please provide url for {url} \nlike: https://{url}")
                failure_count += 1
                failure_url.append(url)
                continue

        except requests.exceptions.SSLError as e:
            # Increment failure count
            failure_count += 1
            failure_url.append(url)
            pass
        except requests.exceptions.ConnectionError as e:
            failure_count += 1
            failure_url.append(url)
            pass
        except Exception as e:
            failure_count += 1
            failure_url.append(url)
            exit(f"[Error] Failure {url}: {e}")
            pass

        headers = response.headers
        status_code = response.status_code

        if status_code in range(200, 299):
            print(f"\n{Fore.CYAN + url + Style.RESET_ALL}", " ", Fore.GREEN + str(status_code) + Style.RESET_ALL)

        elif status_code in range(300, 399):
            print(f"\n{Fore.CYAN + url + Style.RESET_ALL}", " ", Fore.BLUE + str(status_code) + Style.RESET_ALL)

        elif status_code in range(400, 499):
            print(f"\n{Fore.CYAN + url + Style.RESET_ALL}", " ", Fore.RED + str(status_code) + Style.RESET_ALL)

        elif status_code in range(500, 599):
            print(f"\n{Fore.CYAN + url + Style.RESET_ALL}", " ", Fore.RED + str(status_code) + Style.RESET_ALL)

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
    return failure_count, failure_url


def failure(failure_url):
    print()
    table = []
    subject = Fore.RED + "Failure URLS:" + Style.RESET_ALL
    for url in failure_url:
        table.append([url])

    print(subject, "\n")
    print(tabulate(table, headers=["URLs"], tablefmt="github", showindex=range(len(table))))
    print()


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
    start = time.time()
    parser = argparse.ArgumentParser(description="Check security headers for URLs\n")
    parser.add_argument("-f", "--file", dest="urls_file", required=False,
                        help="Path to a text file containing URLs, each url in a line (required)")
    parser.add_argument("-r", "--report", action="store_true", help="Show a summery report")
    parser.add_argument("-k", "--failure", action="store_true", help="Show failure URL")
    parser.add_argument("-i", "--ignore-ssl-errors", action="store_false", default=True,
                        help="Ignore SSL verification errors ")
    args = parser.parse_args()

    if not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin.readlines()]
        all_url = len(urls)
        if urls:
            failure_count, failure_url = check_security_headers(urls, ignore_ssl_errors=args.ignore_ssl_errors)
        else:
            print("File is empty")

    else:
        if args.urls_file:
            # Read URLs from the file
            urls = read_urls_from_file(args.urls_file)
            all_url = len(urls)

            # Check security headers if URLs were read successfully
            if urls:
                failure_count, failure_url = check_security_headers(urls, ignore_ssl_errors=args.ignore_ssl_errors)
        else:
            print("Please enter your urls file. Example -f urls.txt")

    end = time.time()
    duration = end - start
    duration_process = convert_duration(duration)

    if args.failure:
        failure(failure_url)

    if args.report:
        report(all_url, duration_process, failure_count)
