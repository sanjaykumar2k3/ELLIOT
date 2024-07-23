# ELLIOT - Vulnerability Testing Tool

ELLIOT is a multi-threaded vulnerability testing tool designed to identify potential security issues in web applications. It supports testing for SQL Injection, OS Command Injection, File Upload Vulnerability, and Cross-Site Scripting (XSS).

## Features

- **SQL Injection Testing**
- **OS Command Injection Testing**
- **File Upload Vulnerability Testing**
- **Cross-Site Scripting (XSS) Testing**

## Requirements

- Python 3.x
- `requests` library

Install the `requests` library using pip if you haven't already:

```sh
pip install requests

Usage

Clone the repository:
sh
git clone https://github.com/sanjaykumar2k3/elliot.git
cd elliot
Create a payload file for each type of test you want to perform. For example, sql_payloads.txt for SQL Injection, os_command_payloads.txt for OS Command Injection, file_upload_payloads.txt for File Upload, and xss_payloads.txt for XSS.


Run the program:
sh
python elliot.py
Follow the prompts to enter the URL and select the tests to perform. You will be asked to provide the filenames for the payloads. Ensure the files are in the same directory or provide the full path.
Example



-----------------------ELLIOT-----------------------
Enter the URL of the page to test: http://example.com

Select tests to perform:
1. SQL Injection
2. OS Command Injection
3. File Upload Vulnerability
4. Cross-Site Scripting (XSS)
Enter the numbers of the tests to perform, separated by commas (e.g., 1,3,4): 1,4

Enter the filename or directory for SQL Injection payloads: sql_payloads.txt

Testing SQL Injection...
Potential SQL Injection found with payload: ' OR '1'='1
Response: ...

Enter the filename or directory for XSS payloads: xss_payloads.txt

Testing Cross-Site Scripting (XSS)...
Potential XSS found with payload: <script>alert(1)</script>
Response snippet: ...
Exit

You can exit the program at any prompt by typing exit.

