# Elliot

Elliot is a Python tool designed to test web applications for common vulnerabilities such as SQL Injection, OS Command Injection, File Upload Vulnerability, and Cross-Site Scripting (XSS).

## Features

- **SQL Injection**: Detects SQL Injection vulnerabilities by sending malicious payloads.
- **OS Command Injection**: Detects OS Command Injection vulnerabilities by sending command injection payloads.
- **File Upload Vulnerability**: Tests for file upload vulnerabilities by uploading various types of malicious files.
- **Cross-Site Scripting (XSS)**: Detects XSS vulnerabilities by injecting scripts and other malicious payloads.

## Requirements

- Python 3.x
- `requests` library

## Installation

1. Clone the repository:
    ```sh
    https://github.com/sanjaykumar2k3/ELLIOT.git
    cd ELLIOT
    ```

2. Install the required libraries:
    ```sh
    pip install requests
    ```

## Usage

1. Run the script:
    ```sh
    python ELLIOT.py
    ```

2. Follow the prompts to enter the URL of the page to test and select the tests to perform.

## Example

```sh
Enter the URL of the page to test: http://example.com/vulnerable_page

Select tests to perform:
1. SQL Injection
2. OS Command Injection
3. File Upload Vulnerability
4. Cross-Site Scripting (XSS)
Enter the numbers of the tests to perform, separated by commas (e.g., 1,3,4): 1,4

Testing SQL Injection...
Potential SQL Injection found with payload: ' OR '1'='1
Response: <html>...</html>

Testing Cross-Site Scripting (XSS)...
Potential XSS found with payload: <script>alert(1)</script>
Response snippet: <html>...</html>
