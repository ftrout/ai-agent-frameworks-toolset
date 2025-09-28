import json
import requests
from typing import Optional, Dict, Any, List
from semantic_kernel.skill_definition import kernel_function
from semantic_kernel import ContextProperties

class NistNvdPlugin:
    """
    A Semantic Kernel plugin for interacting with the NIST NVD APIs.
    Supports CVE and CVE Change History queries with pagination.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cve_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.history_base_url = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

    def _make_request(self, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Internal helper to make API requests and handle errors.
        """
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        response = requests.get(url, params=params, headers=headers, timeout=30)
        if response.status_code == 200:
            return response.json()
        else:
            raise ValueError(f"API request failed: {response.status_code} - {response.text}")

    def _fetch_all_pages(self, url: str, params: Dict[str, Any], result_key: str) -> List[Dict[str, Any]]:
        """
        Helper to fetch all pages of results for paginated APIs.
        
        Args:
            url (str): Base URL for the API endpoint.
            params (Dict[str, Any]): Query parameters including startIndex and resultsPerPage.
            result_key (str): Key in JSON response containing the results list (e.g., 'vulnerabilities' or 'cve_changes').
        
        Returns:
            List[Dict[str, Any]]: Combined list of all results across pages.
        """
        all_results = []
        start_index = params.get("startIndex", 0)
        results_per_page = min(params.get("resultsPerPage", 2000), 2000)  # API max limit
        params["resultsPerPage"] = results_per_page

        while True:
            params["startIndex"] = start_index
            data = self._make_request(url, params)
            results = data.get(result_key, [])
            all_results.extend(results)

            total_results = data.get("totalResults", 0)
            start_index += results_per_page

            if start_index >= total_results or not results:
                break

        return all_results

    @kernel_function(
        description="Retrieve detailed information for a single CVE by its ID (e.g., 'CVE-2023-1234').",
        name="get_cve_by_id"
    )
    def get_cve_by_id(
        self,
        cve_id: str,
        context: ContextProperties = None
    ) -> str:
        """
        Fetches CVE details by ID. No pagination needed for single CVE.
        
        Args:
            cve_id (str): The CVE identifier (e.g., 'CVE-2023-1234').
        
        Returns:
            str: JSON string representation of the CVE data.
        """
        try:
            url = self.cve_base_url
            params = {"cveId": cve_id}
            data = self._make_request(url, params)
            return json.dumps(data, indent=2)
        except ValueError as e:
            return f"Error retrieving CVE {cve_id}: {str(e)}"

    @kernel_function(
        description="Search for CVEs using filters like keywords, dates, CVSS scores, etc. Supports pagination.",
        name="search_cves"
    )
    def search_cves(
        self,
        keyword_search: Optional[str] = None,
        pub_start_date: Optional[str] = None,  # Format: YYYY-MM-DDTHH:MM:SS
        pub_end_date: Optional[str] = None,
        last_mod_start_date: Optional[str] = None,
        last_mod_end_date: Optional[str] = None,
        cvss_v2_severity: Optional[str] = None,  # e.g., 'HIGH'
        cvss_v3_severity: Optional[str] = None,
        cwe_id: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        start_index: int = 0,
        results_per_page: int = 2000,
        fetch_all: bool = False,
        context: ContextProperties = None
    ) -> str:
        """
        Searches for CVEs with flexible parameters. Supports pagination or fetching all results.
        
        Args:
            keyword_search (str): Keyword to search in descriptions, etc.
            pub_start_date (str): Start date for publication (ISO 8601).
            pub_end_date (str): End date for publication (ISO 8601).
            last_mod_start_date (str): Start date for last modification.
            last_mod_end_date (str): End date for last modification.
            cvss_v2_severity (str): CVSS v2 severity (LOW, MEDIUM, HIGH).
            cvss_v3_severity (str): CVSS v3 severity.
            cwe_id (str): CWE identifier (e.g., 'CWE-79').
            vendor (str): Vendor name for CPE filter.
            product (str): Product name for CPE filter.
            start_index (int): Starting index for pagination (default 0).
            results_per_page (int): Number of results per page (max 2000, default 2000).
            fetch_all (bool): If True, fetches all results across pages; else, single page.
        
        Returns:
            str: JSON string of search results, including total count and vulnerabilities.
        """
        try:
            params: Dict[str, Any] = {
                "startIndex": start_index,
                "resultsPerPage": min(results_per_page, 2000)
            }

            if keyword_search:
                params["keywordSearch"] = keyword_search
            if pub_start_date:
                params["pubStartDate"] = pub_start_date
            if pub_end_date:
                params["pubEndDate"] = pub_end_date
            if last_mod_start_date:
                params["lastModStartDate"] = last_mod_start_date
            if last_mod_end_date:
                params["lastModEndDate"] = last_mod_end_date
            if cvss_v2_severity:
                params["cvssV2Severity"] = cvss_v2_severity
            if cvss_v3_severity:
                params["cvssV3Severity"] = cvss_v3_severity
            if cwe_id:
                params["cweId"] = cwe_id
            if vendor:
                params["vendor"] = vendor
            if product:
                params["product"] = product

            if fetch_all:
                results = self._fetch_all_pages(self.cve_base_url, params, "vulnerabilities")
                data = {"totalResults": len(results), "vulnerabilities": results}
            else:
                data = self._make_request(self.cve_base_url, params)

            return json.dumps(data, indent=2)
        except ValueError as e:
            return f"Error searching CVEs: {str(e)}"

    @kernel_function(
        description="Retrieve the change history for a specific CVE. No pagination needed for single CVE.",
        name="get_cve_change_history"
    )
    def get_cve_change_history(
        self,
        cve_id: str,
        context: ContextProperties = None
    ) -> str:
        """
        Fetches the history of changes made to a CVE.
        
        Args:
            cve_id (str): The CVE identifier (e.g., 'CVE-2023-1234').
        
        Returns:
            str: JSON string representation of the CVE change history.
        """
        try:
            url = self.history_base_url
            params = {"cveId": cve_id}
            data = self._make_request(url, params)
            return json.dumps(data, indent=2)
        except ValueError as e:
            return f"Error retrieving CVE history for {cve_id}: {str(e)}"

    @kernel_function(
        description="Search CVE change history with date filters. Supports pagination.",
        name="search_cve_history"
    )
    def search_cve_history(
        self,
        pub_start_date: Optional[str] = None,
        pub_end_date: Optional[str] = None,
        start_index: int = 0,
        results_per_page: int = 2000,
        fetch_all: bool = False,
        context: ContextProperties = None
    ) -> str:
        """
        Searches for CVE change history entries within date ranges.
        
        Args:
            pub_start_date (str): Start date for publication (ISO 8601).
            pub_end_date (str): End date for publication (ISO 8601).
            start_index (int): Starting index for pagination (default 0).
            results_per_page (int): Number of results per page (default 2000).
            fetch_all (bool): If True, fetches all results across pages; else, single page.
        
        Returns:
            str: JSON string of history search results.
        """
        try:
            params: Dict[str, Any] = {
                "startIndex": start_index,
                "resultsPerPage": min(results_per_page, 2000)
            }

            if pub_start_date:
                params["pubStartDate"] = pub_start_date
            if pub_end_date:
                params["pubEndDate"] = pub_end_date

            if fetch_all:
                results = self._fetch_all_pages(self.history_base_url, params, "cve_changes")
                data = {"totalResults": len(results), "cve_changes": results}
            else:
                data = self._make_request(self.history_base_url, params)

            return json.dumps(data, indent=2)
        except ValueError as e:
            return f"Error searching CVE history: {str(e)}"