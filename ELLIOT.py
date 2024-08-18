import os
import requests
import concurrent.futures
from bs4 import BeautifulSoup
import urllib.parse

# Function to read payloads from a file
def read_payloads(filename):
    try:
        with open(filename, 'r') as file:
            payloads = file.read().split(',')
        return [payload.strip() for payload in payloads if payload.strip()]
    except PermissionError:
        print(f"Permission denied: Unable to access {filename}")
        return []
    except Exception as e:
        print(f"Error reading payloads from {filename}: {e}")
        return []

# Function to read file upload payloads from a file
def read_file_upload_payloads(filename):
    try:
        with open(filename, 'r') as file:
            lines = file.read().split('\n')
        payloads = {}
        for line in lines:
            if line.strip():
                parts = line.split(':', 1)
                if len(parts) == 2:
                    field, content = parts
                    if field.strip() not in payloads:
                        payloads[field.strip()] = {}
                    payloads[field.strip()][f'file_{len(payloads[field.strip()])}'] = content.strip()
                else:
                    print(f"Malformed payload line: {line}")
        return payloads
    except PermissionError:
        print(f"Permission denied: Unable to access {filename}")
        return {}
    except Exception as e:
        print(f"Error reading file upload payloads from {filename}: {e}")
        return {}

# Function to test a single SQL Injection payload with specific field values
def test_sql_payload(url, payload, field):
    try:
        # Set default values for the other field based on the field being tested
        params = {'username': 'admin', 'password': 'Password'}
        params[field] = payload

        response = requests.get(url, params=params, timeout=5)

        # Check for common SQL error messages in the response if status code is 200
        if response.status_code == 200:
            error_indicators = [
                "syntax error", "SQL", "database error", "warning: mysql", 
                "unclosed quotation mark", "sqlstate", "syntax;", "unterminated string"
            ]
            for indicator in error_indicators:
                if indicator.lower() in response.text.lower():
                    return f"Potential SQL Injection found with payload: {payload} on field: {field}"
    except requests.exceptions.RequestException as e:
        return f"Request failed for payload: {payload}\nError: {e}"
    return None

# Function to test SQL Injection with updated payload handling
def test_sql_injection(url, payloads):
    fields = ['username', 'password']
    count = 0
    for field in fields:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(lambda p: test_sql_payload(url, p, field), payloads))
        vulnerabilities = [result for result in results if result]
        for result in results:
            if result:
                count += 1
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(vuln)
        else:
            print(f"No SQL Injection vulnerabilities found for field: {field}.")
    print(f"Processed {len(payloads)} SQL Injection payloads, with {count} potential vulnerabilities found.")

# Function to test a single OS Command Injection payload
def test_os_command_payload(url, payload, field):
    try:
        response = requests.get(url, params={field: payload}, timeout=5)
        if 'root:x' in response.text or any(cmd in response.text for cmd in ['bin', 'usr', 'etc']):
            return f"Potential OS Command Injection found with payload: {payload} on field: {field}\nResponse: {response.text[:200]}"
    except requests.exceptions.RequestException as e:
        return f"Request failed for payload: {payload}\nError: {e}"
    return None

# Function to test OS Command Injection
def test_os_command_injection(url, payloads):
    fields = ['input']  # Adjust as needed based on actual field names
    count = 0
    for field in fields:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(lambda p: test_os_command_payload(url, p, field), payloads))
        vulnerabilities = [result for result in results if result]
        for result in results:
            if result:
                count += 1
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(vuln)
        else:
            print(f"No OS Command Injection vulnerabilities found for field: {field}.")
    print(f"Processed {len(payloads)} OS Command Injection payloads, with {count} potential vulnerabilities found.")

# Function to test a single file upload
def test_file_upload_single(url, field, filename, content):
    files = {field: (filename, content)}
    try:
        response = requests.post(url, files=files, timeout=5)
        if response.status_code == 200:
            return f"Uploaded {filename} successfully on field: {field}"
        else:
            return f"Failed to upload {filename} on field: {field}\nResponse Code: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Request failed for file: {filename} on field: {field}\nError: {e}"

# Function to test File Upload Vulnerability
def test_file_upload(url, files):
    count = 0
    for field, file_data in files.items():
        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = list(executor.map(lambda f: test_file_upload_single(url, field, f[0], f[1]), file_data.items()))
        for result in results:
            if "Uploaded" in result:
                count += 1
            print(result)  # Print the results, without response snippets
    print(f"Processed {len(files)} file upload payloads, with {count} files uploaded successfully.")

# Function to test Cross-Site Scripting (XSS) without using cookies
def test_xss(url, payload_file):
    with open(payload_file, 'r') as f:
        payloads = f.read().split(',')

    session = requests.Session()

    try:
        response = session.get(url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Failed to connect to {url}: {e}")
        return

    soup = BeautifulSoup(response.content, 'html.parser')
    forms = soup.find_all('form')

    if not forms:
        print("No forms found on the page.")
        return

    vulnerabilities = []

    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()
        inputs = form.find_all('input')
        
        form_url = urllib.parse.urljoin(url, action)

        for payload in payloads:
            data = {}
            for input_tag in inputs:
                input_name = input_tag.get('name')
                input_type = input_tag.get('type', 'text')
                input_value = payload if input_type in ['text', 'search'] else input_tag.get('value', '')

                if input_name:
                    data[input_name] = input_value

            if method == 'post':
                response = session.post(form_url, data=data)
            else:
                response = session.get(form_url, params=data)

            if payload in response.text:
                vulnerabilities.append((payload, form_url))

    if vulnerabilities:
        for payload, form_url in vulnerabilities:
            print(f"[!] Potential XSS vulnerability detected with payload: {payload}")
            print(f"Form action: {form_url}")
    else:
        print("[+] No XSS vulnerabilities detected with the provided payloads.")

# Function to exit the program
def exit_program():
    print("Exiting the program.")
    exit()

# Main function to prompt user for input and run tests
def main():
    print("-----------------------ELLIOT-----------------------")
    print(" ")
    
    while True:
        url = input("Enter the URL of the page to test: ").strip()
        if url.lower() == "exit":
            exit_program()

        # Check if the URL is reachable
        try:
            response = requests.get(url, timeout=5)
            response.raise_for_status()
        except requests.exceptions.RequestException:
            print(f"Error: The host is unreachable or invalid URL, please check the URL.")
            continue

        print("\nSelect tests to perform:")
        print("1. SQL Injection")
        print("2. OS Command Injection")
        print("3. File Upload Vulnerability")
        print("4. Cross-Site Scripting (XSS)")
        selected_tests = input("Enter the numbers of the tests to perform, separated by commas (e.g., 1,3,4): ").split(',')
        if "exit" in selected_tests:
            exit_program()

        # Read payloads from files based on selected tests
        if '1' in selected_tests:
            sql_payloads_file = input("Enter the filename or directory for SQL Injection payloads: ").strip()
            if sql_payloads_file.lower() == "exit":
                exit_program()
            sql_payloads = read_payloads(sql_payloads_file)
            if sql_payloads:
                print("\nTesting SQL Injection...")
                test_sql_injection(url, sql_payloads)
            else:
                print("No valid SQL Injection payloads found.")

        if '2' in selected_tests:
            os_command_payloads_file = input("Enter the filename or directory for OS Command Injection payloads: ").strip()
            if os_command_payloads_file.lower() == "exit":
                exit_program()
            os_command_payloads = read_payloads(os_command_payloads_file)
            if os_command_payloads:
                print("\nTesting OS Command Injection...")
                test_os_command_injection(url, os_command_payloads)
            else:
                print("No valid OS Command Injection payloads found.")

        if '3' in selected_tests:
            file_upload_payloads_file = input("Enter the filename or directory for File Upload payloads: ").strip()
            if file_upload_payloads_file.lower() == "exit":
                exit_program()
            file_upload_payloads = read_file_upload_payloads(file_upload_payloads_file)
            if file_upload_payloads:
                print("\nTesting File Upload Vulnerability...")
                test_file_upload(url, file_upload_payloads)
            else:
                print("No valid File Upload payloads found.")

        if '4' in selected_tests:
            xss_payloads_file = input("Enter the filename or directory for XSS payloads: ").strip()
            if xss_payloads_file.lower() == "exit":
                exit_program()
            print("\nTesting Cross-Site Scripting (XSS)...")
            test_xss(url, xss_payloads_file)

        print("\nTests completed.")
        
        # Ask if the user wants to test another URL
        another_test = input("Do you want to test another URL? (yes/no): ").strip().lower()
        if another_test not in ['yes', 'y']:
            exit_program()

if __name__ == "__main__":
    main()

