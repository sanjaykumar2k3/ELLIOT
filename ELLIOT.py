import os
import requests
import concurrent.futures

# Function to read payloads from a file
def read_payloads(filename):
    with open(filename, 'r') as file:
        payloads = file.read().split(',')
    return [payload.strip() for payload in payloads]

# Function to read file upload payloads from a file
def read_file_upload_payloads(filename):
    with open(filename, 'r') as file:
        lines = file.read().split('\n')
    payloads = {}
    for line in lines:
        if line.strip():
            filename, content = line.split(':', 1)
            payloads[filename.strip()] = content.strip()
    return payloads

# Function to test a single SQL Injection payload
def test_sql_payload(url, payload):
    response = requests.get(url, params={'input': payload})
    if "SQL" in response.text or "syntax error" in response.text:
        return f"Potential SQL Injection found with payload: {payload}\nResponse: {response.text[:200]}"  # Print a snippet of the response
    return None

# Function to test SQL Injection
def test_sql_injection(url, payloads):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda p: test_sql_payload(url, p), payloads))
    vulnerabilities = [result for result in results if result]
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(vuln)
    else:
        print("No SQL Injection vulnerabilities found.")

# Function to test a single OS Command Injection payload
def test_os_command_payload(url, payload):
    response = requests.get(url, params={'input': payload})
    if 'root:x' in response.text or any(cmd in response.text for cmd in ['bin', 'usr', 'etc']):
        return f"Potential OS Command Injection found with payload: {payload}\nResponse: {response.text[:200]}"  # Print a snippet of the response
    return None

# Function to test OS Command Injection
def test_os_command_injection(url, payloads):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda p: test_os_command_payload(url, p), payloads))
    vulnerabilities = [result for result in results if result]
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(vuln)
    else:
        print("No OS Command Injection vulnerabilities found.")

# Function to test a single file upload
def test_file_upload_single(url, filename, content):
    file = {'file': (filename, content)}
    response = requests.post(url, files=file)
    if response.status_code == 200:
        return f"Uploaded {filename} successfully\nResponse: {response.text[:200]}"  # Print a snippet of the response
    else:
        return f"Failed to upload {filename}\nResponse Code: {response.status_code}"

# Function to test File Upload Vulnerability
def test_file_upload(url, files):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda f: test_file_upload_single(url, f[0], f[1]), files.items()))
    for result in results:
        print(result)

# Function to test a single XSS payload
def test_xss_payload(url, params, key, payload):
    test_params = params.copy()
    test_params[key] = payload
    response = requests.get(url, params=test_params)
    if payload in response.text:
        return f"Potential XSS found with payload: {payload}\nResponse snippet: {response.text[:200]}"  # Print a snippet of the response
    return None

# Function to test Cross-Site Scripting (XSS)
def test_xss(url, params, payloads):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda p: test_xss_payload(url, params, list(params.keys())[0], p), payloads))
    vulnerabilities = [result for result in results if result]
    if vulnerabilities:
        for vuln in vulnerabilities:
            print(vuln)
    else:
        print("No Cross-Site Scripting (XSS) vulnerabilities found.")

# Main function to prompt user for input and run tests
def main():
    print("-----------------------ELLIOT-----------------------")
    print(" ")
    while True:
        url = input("Enter the URL of the page to test: ").strip()

        print("\nSelect tests to perform:")
        print("1. SQL Injection")
        print("2. OS Command Injection")
        print("3. File Upload Vulnerability")
        print("4. Cross-Site Scripting (XSS)")
        selected_tests = input("Enter the numbers of the tests to perform, separated by commas (e.g., 1,3,4): ").split(',')

        # Read payloads from files based on selected tests
        if '1' in selected_tests:
            sql_payloads_file = input("Enter the filename or directory for SQL Injection payloads: ").strip()
            sql_payloads = read_payloads(sql_payloads_file)
            print("\nTesting SQL Injection...")
            test_sql_injection(url, sql_payloads)

        if '2' in selected_tests:
            os_command_payloads_file = input("Enter the filename or directory for OS Command Injection payloads: ").strip()
            os_command_payloads = read_payloads(os_command_payloads_file)
            print("\nTesting OS Command Injection...")
            test_os_command_injection(url, os_command_payloads)

        if '3' in selected_tests:
            file_upload_payloads_file = input("Enter the filename or directory for File Upload payloads: ").strip()
            file_upload_payloads = read_file_upload_payloads(file_upload_payloads_file)
            print("\nTesting File Upload Vulnerability...")
            test_file_upload(url, file_upload_payloads)

        if '4' in selected_tests:
            xss_payloads_file = input("Enter the filename or directory for XSS payloads: ").strip()
            xss_payloads = read_payloads(xss_payloads_file)
            params = {'search': 'test'}  # Adjust this according to your parameter
            print("\nTesting Cross-Site Scripting (XSS)...")
            test_xss(url, params, xss_payloads)

        another_test = input("\nDo you want to test another URL? (yes/no): ").strip().lower()
        if another_test != 'yes':
            break

if __name__ == "__main__":
    main()
