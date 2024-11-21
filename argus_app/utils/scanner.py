import requests
import json
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs
from models import db, ScanResult, Endpoint, Vulnerability
import concurrent.futures

class APIScanner:
    def __init__(self):
        self.allowed_status_codes = [200, 201, 301, 302, 403]

    def extract_base_url_and_params(self, url):
        parsed_url = urlparse(url)
        base_url = parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path
        params = parse_qs(parsed_url.query)
        return base_url, params

    def test_endpoint(self, endpoint, method='GET', data=None):
        """
        Test a specific endpoint.
        
        :param endpoint: The API endpoint to test.
        :param method: HTTP method (e.g., GET, POST, PUT).
        :param data: Data payload for POST/PUT requests.
        :return: Response object or error message.
        """
        url = urljoin(self.base_url, endpoint)
        try:
            if method == 'GET':
                response = requests.get(url, headers=self.headers)
            elif method == 'POST':
                response = requests.post(url, headers=self.headers, json=data)
            elif method == 'PUT':
                response = requests.put(url, headers=self.headers, json=data)
            elif method == 'DELETE':
                response = requests.delete(url, headers=self.headers)
            else:
                return f"Unsupported HTTP method: {method}"

            return response
        except requests.RequestException as e:
            return f"Error testing endpoint {url}: {e}"

    # Web crawling
    def scan_paths(self, url, user_id):
        """
        Unified function to scan paths (common paths and fuzzing directories).
        
        :param url: Base URL to scan.
        :param wordlist_file: Path to the wordlist file.
        :param user_id: ID of the user performing the scan.
        :return: Results of the scan.
        """
        wordlist_file = 'db\dicc.txt'

        url_dict = {status: [] for status in self.allowed_status_codes}  # Dictionary to store results by status code
        endpoints = []  # List to store discovered endpoints
        
        def scan_path(path):
            full_url = f"{url.rstrip('/')}/{path.strip()}"
            try:
                response = requests.get(full_url, allow_redirects=True, timeout=5)
                if response.status_code in self.allowed_status_codes:
                    url_dict[response.status_code].append(full_url)
                    endpoints.append({
                        "url": full_url,
                        "status_code": response.status_code
                    })
            except requests.RequestException as e:
                pass
        # Load wordlist
        try:
            with open(wordlist_file, "r") as file:
                wordlist = [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            return None

        # Scan paths using multithreading for efficiency
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(scan_path, wordlist)
        
        # Save results to the database
        self.save_scan_results(url, endpoints, user_id)
        
        return url_dict  # Return the results for additional processing if needed

    def save_scan_results(self, url, endpoints, user_id):
        """
        Save scan results to the database.

        :param url: Original URL scanned.
        :param endpoints: List of discovered endpoints.
        :param user_id: ID of the user performing the scan.
        """
        try:
            # Calculate default or placeholder values
            risk_level = "Low"  # Default risk level (can be updated with actual logic later)
            score = 0.0  # Default score (can be calculated based on vulnerabilities later)
            scan_duration = 0.0  # Placeholder duration (if not calculated during the scan)

            # Create a new ScanResult entry
            scan_result = ScanResult(
                original_endpoint=url,
                open_endpoints=json.dumps([endpoint["url"] for endpoint in endpoints]),  # Store URLs as JSON
                vulnerabilities_found=json.dumps([]),  # Initially empty; can be populated with vulnerability scans
                risk_level=risk_level,  # Default risk level
                score=score,  # Default score
                scan_duration=scan_duration,  # Placeholder duration
                timestamp=datetime.utcnow(),
                user_id=user_id,
                description=None  # Optional description
            )
            db.session.add(scan_result)
            db.session.commit()

            # Add endpoints to the Endpoint table
            for endpoint in endpoints:
                endpoint_entry = Endpoint(
                    url=endpoint["url"],
                    status_code=endpoint["status_code"],
                    scan_id=scan_result.id
                )
                db.session.add(endpoint_entry)

            db.session.commit()
            print(f"Scan results successfully saved for {url}!")
        except Exception as e:
            db.session.rollback()
            print(f"Error saving scan results to the database: {e}")

    # IDOR Scan
    def test_idor(self, url, parameter, user_id=1):
        """
        Test for Insecure Direct Object References (IDOR).
        
        :param endpoint: The API endpoint (base URL).
        :param parameter: The parameter to test for IDOR (e.g., user ID).
        :param user_id: ID of the user initiating the test.
        :return: Results of the IDOR test.
        """
        # Prepare test cases with different parameter values
        test_values = [1, 2, 3, 4, 34, 88, 69, 10, 20, 45, 99999]  # Example parameter values (can load from file or generate dynamically)
        base_url, param = self.extract_base_url_and_params(url)
        key = next(iter(param.keys()))
        
        results = []  # Store results of each test case

        for test_value in test_values:
            # Construct the test URL
            new_url = f"{base_url}?{key}={param['id'][0]}"
            try:
                # Send the GET request
                response = requests.get(new_url, timeout=5)

                if response.status_code == 200:
                    # Analyze the response content for sensitive data exposure
                    exposed_data = self.analyze_idor_response(response.text)

                    if exposed_data:
                        result = {
                            "parameter_value": test_value,
                            "status_code": response.status_code,
                            "data_exposed": True,
                            "exposed_data": exposed_data
                        }
                        results.append(result)
                    else:
                        result = {
                            "parameter_value": test_value,
                            "status_code": response.status_code,
                            "data_exposed": False
                        }
                        results.append(result)
                else:
                    result = {
                        "parameter_value": test_value,
                        "status_code": response.status_code,
                        "data_exposed": False
                    }
                    results.append(result)

            except requests.RequestException as e:
                results.append({
                    "parameter_value": test_value,
                    "status_code": None,
                    "data_exposed": False,
                    "error": str(e)
                })

        # Save results to the database
        self.save_idor_results(base_url, key, results, user_id)

        return results  # Return results for further processing or reporting


    def analyze_idor_response(self, response_text):
        """
        Analyze the response text to detect sensitive data exposure.
        
        :param response_text: The response content as a string.
        :return: Exposed data (if any), or None.
        """
        sensitive_keywords = ["username", "email", "password", "token", "balance", "account"]
        exposed_data = []

        for keyword in sensitive_keywords:
            if keyword in response_text.lower():
                exposed_data.append(keyword)

        return exposed_data if exposed_data else None


    def save_idor_results(self, base_url, key, results, user_id):
        """
        Save IDOR test results to the database.
        
        :param endpoint: The tested endpoint.
        :param parameter: The parameter tested for IDOR.
        :param results: List of test results.
        :param user_id: ID of the user initiating the test.
        """
        try:
            # Save each test result as a Vulnerability entry
            for result in results:
                if result.get("data_exposed"):
                    vulnerability = Vulnerability(
                        scan_id=12345,  # Link this to an existing ScanResult if available
                        endpoint=f"{base_url}?{key}={result['parameter_value']}",
                        vulnerability_type="IDOR",
                        owasp_category="Broken Access Control",
                        severity="High",
                        description=f"Exposed data: {', '.join(result['exposed_data'])}",
                        remediation="Validate and authorize requests to ensure only authorized users can access resources."
                    )
                    db.session.add(vulnerability)

            db.session.commit()
        except Exception as e:
            print(e)
            db.session.rollback()

    # SQL SCAN
    def test_sql_injection(self, base_url, parameter_name, user_id=1):
        """
        Test for SQL Injection vulnerabilities.

        :param endpoint: The API endpoint to test.
        :param parameter_name: The name of the query parameter to test.
        :param user_id: ID of the user initiating the test.
        :return: List of SQL Injection test results.
        """

        # Common SQL Injection payloads
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' OR 1=1 --",
            "' UNION SELECT null, null, null --",
            "' AND 1=0 UNION SELECT username, password FROM users --",
            "\" OR \"1\"=\"1",
            "admin' --",
            "' OR sleep(5) --",
            "' AND '1'='1"
        ]

        results = []  # Store the results of each test case

        for payload in payloads:
            # Construct the test URL with the payload
            params = {parameter_name: payload}
            try:
                response = requests.get(base_url, params=params, timeout=5)

                if response.status_code == 200:
                    # Analyze response for SQL error keywords
                    error_keywords = ["sql", "syntax", "query", "database", "exception"]
                    if any(keyword in response.text.lower() for keyword in error_keywords):
                        result = {
                            "payload": payload,
                            "status_code": response.status_code,
                            "vulnerable": True,
                            "error_message": self.extract_sql_error(response.text)
                        }
                        results.append(result)
                    else:
                        result = {
                            "payload": payload,
                            "status_code": response.status_code,
                            "vulnerable": False
                        }
                        results.append(result)
                else:
                    result = {
                        "payload": payload,
                        "status_code": response.status_code,
                        "vulnerable": False
                    }
                    results.append(result)
            except requests.RequestException as e:
                results.append({
                    "payload": payload,
                    "status_code": None,
                    "vulnerable": False,
                    "error": str(e)
                })

        # Save results to the database
        self.save_sqli_results(base_url, parameter_name, results, user_id)

        return results  # Return results for further processing or reporting

    def extract_sql_error(self, response_text):
        """
        Extract SQL error messages from the response text.

        :param response_text: The response content as a string.
        :return: Extracted error message or None.
        """
        error_keywords = ["sql", "syntax", "query", "database", "exception"]
        for keyword in error_keywords:
            if keyword in response_text.lower():
                return keyword  # Return the first matching keyword as the error
        return None

    def save_sqli_results(self, endpoint, parameter_name, results, user_id):
        """
        Save SQL Injection test results to the database.

        :param endpoint: The tested endpoint.
        :param parameter_name: The parameter tested for SQL Injection.
        :param results: List of test results.
        :param user_id: ID of the user initiating the test.
        """
        try:
            # Save each SQL Injection result as a Vulnerability entry
            for result in results:
                if result.get("vulnerable"):
                    vulnerability = Vulnerability(
                        scan_id=None,  # Link this to an existing ScanResult if available
                        endpoint=f"{endpoint}?{parameter_name}={result['payload']}",
                        vulnerability_type="SQL Injection",
                        owasp_category="Injection",
                        severity="High",
                        description=f"Detected SQL Injection with payload: {result['payload']} - Error: {result.get('error_message')}",
                        remediation="Sanitize and validate all user inputs. Use parameterized queries and ORMs to prevent SQL Injection."
                    )
                    db.session.add(vulnerability)

            db.session.commit()
            print(f"SQL Injection results successfully saved for endpoint: {endpoint}")
        except Exception as e:
            db.session.rollback()
            print(f"Error saving SQL Injection results to the database: {e}")
            
    def scan_api(self, endpoint):
        """
        Scan all endpoints for vulnerabilities.
        
        :param endpoints: List of endpoints to scan.
        :return: Scan results.
        """
        if not endpoint.endswith("/"):
            endpoint = endpoint + '/'

        results = self.check_common_paths(endpoint)

        # idor_result = self.test_idor(endpoint, "1")  # Example parameter
        # sql_result = self.test_sql_injection(endpoint, "id", "' OR '1'='1")
        # results.append({
        #     "endpoint": endpoint,
        #     "IDOR Test": idor_result,
        #     "SQL Injection Test": sql_result,
        # })
        return results


