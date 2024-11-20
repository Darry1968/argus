import requests
import json
from urllib.parse import urljoin, urlparse, parse_qs
from models import db, ScanResult

class APIScanner:
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
    def check_common_paths(self, url):
        found = 0
        endpoints = []
        result = {"success": True, "vulnerabilities": ["XSS", "SQLi"]}
        with open('db\common_paths.txt','r') as file:
            for endpoint in file:
                furl = url + endpoint.strip()
                try:
                    req = requests.get(furl)
                    if req.status_code == 200:
                        found = 1
                        endpoints.append(url + endpoint)
                except Exception as e:
                    pass

            if found == 0:
                return "Nothing was found"
        
        # after scan
        scan = ScanResult(
            original_endpoint=url,
            endpoints=json.dumps(endpoints),
            result=json.dumps(result),
            user_id=1
        )

        db.session.add(scan)
        db.session.commit()

        return endpoints

    # Vulnerability Scan
    def test_idor(self, endpoint, parameter):
        """
        Test for Insecure Direct Object References (IDOR).
        
        :param endpoint: The API endpoint.
        :param parameter: A parameter to modify (e.g., resource ID).
        :return: Result of the test.
        """
        url = urljoin(self.base_url, f"{endpoint}/{parameter}")
        response = self.test_endpoint(url)
        if isinstance(response, str):
            return response  # Error message

        # Analyze response to check for IDOR
        if response.status_code == 200:
            return f"Potential IDOR detected on {url} (HTTP 200)."
        return f"No IDOR detected on {url} (HTTP {response.status_code})."

    def test_sql_injection(self, url, parameter_name, payload):
        """
        Test for SQL Injection.
        
        :param endpoint: The API endpoint.
        :param parameter_name: The name of the query parameter to test.
        :param payload: The SQL payload to inject.
        :return: Result of the test.
        """
        params = {parameter_name: payload}
        response = self.test_endpoint(url, method='GET', data=params)
        if isinstance(response, str):
            return response  # Error message

        # Analyze response for SQL injection indications
        error_keywords = ["sql", "syntax", "query", "database", "exception"]
        if any(keyword in response.text.lower() for keyword in error_keywords):
            return f"Potential SQL injection detected on {url} with payload {payload}."
        return f"No SQL injection detected on {url} with payload {payload}."

    def Broken_User_Authentication(self, url):
        base_url, params = self.extract_base_url_and_params(url)
        print("Base URL:", base_url)
        print("Parameters:", params)

        with open('./db/ids.txt','r') as f: 
            for other_user_id in f:
                other_user_id = other_user_id.strip()
                response = requests.get(base_url, params={"id": other_user_id})
                if response.status_code == 200:
                    print(f"{other_user_id} - {response.text}")

                else:
                    print(f"\rThere is no user with user ID {other_user_id}. Status code: {response.status_code}",end="")
                
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


