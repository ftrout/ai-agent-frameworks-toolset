import json
import requests
from typing import Dict, Any, Optional, List

from semantic_kernel.skill_definition import kernel_function

class OtxPlugin:
    """
    A Semantic Kernel plugin for interacting with the AlienVault OTX (Open Threat Exchange) API v1.
    This plugin provides functions for all major endpoints, including pulses, indicators, groups, and submissions.
    
    Note: Authentication requires an API key in the X-OTX-API-KEY header. Public API has rate limits.
    For binary responses (e.g., file downloads), functions return bytes where applicable.
    Base URL: https://otx.alienvault.com/api/v1/
    """

    def __init__(self, api_key: str):
        """
        Initialize the OTX plugin.
        
        :param api_key: Your OTX API key (obtain from https://otx.alienvault.com/my-api-keys).
        """
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1/"
        self.headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    # User Endpoints

    @kernel_function(
        description="Get information about the current user.",
        name="get_current_user"
    )
    def get_current_user(
        self
    ) -> Dict[str, Any]:
        """
        Retrieves the current user's information.
        
        :return: Dictionary containing user data.
        """
        url = f"{self.base_url}users/me"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    # Pulses Endpoints

    @kernel_function(
        describe="List subscribed pulses.",
        name="list_subscribed_pulses"
    )
    def list_subscribed_pulses(
        self,
        limit: Optional[int] = 50,
        page: Optional[int] = 1,
        modified_since: Optional[str] = None  # ISO 8601 format
    ) -> Dict[str, Any]:
        """
        Retrieves a list of pulses the user is subscribed to.
        
        :param limit: Maximum number of pulses to return.
        :param page: Page number.
        :param modified_since: Filter by modification date.
        :return: Dictionary containing pulse list.
        """
        params = {"limit": limit, "page": page}
        if modified_since:
            params["modified_since"] = modified_since
        url = f"{self.base_url}pulses/subscribed"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Search for pulses by query.",
        name="search_pulses"
    )
    def search_pulses(
        self,
        q: str,
        limit: Optional[int] = 50,
        page: Optional[int] = 1
    ) -> Dict[str, Any]:
        """
        Searches for pulses matching the query.
        
        :param q: Search query.
        :param limit: Maximum number of pulses.
        :param page: Page number.
        :return: Dictionary containing search results.
        """
        params = {"q": q, "limit": limit, "page": page}
        url = f"{self.base_url}pulses"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get details for a specific pulse.",
        name="get_pulse"
    )
    def get_pulse(
        self,
        pulse_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves details for a pulse.
        
        :param pulse_id: The pulse ID.
        :return: Dictionary containing pulse data.
        """
        url = f"{self.base_url}pulses/{pulse_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get indicators for a specific pulse.",
        name="get_pulse_indicators"
    )
    def get_pulse_indicators(
        self,
        pulse_id: str,
        indicator_type: Optional[str] = None  # e.g., 'IPv4', 'domain'
    ) -> Dict[str, Any]:
        """
        Retrieves indicators from a pulse.
        
        :param pulse_id: The pulse ID.
        :param indicator_type: Filter by type (optional).
        :return: Dictionary containing indicators.
        """
        url = f"{self.base_url}pulses/{pulse_id}/indicators"
        params = {}
        if indicator_type:
            params["type"] = indicator_type
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Create a new pulse.",
        name="create_pulse"
    )
    def create_pulse(
        self,
        name: str,
        description: str,
        tlp: str = "white",  # white, green, amber, red
        indicators: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Creates a new pulse.
        
        :param name: Pulse name.
        :param description: Pulse description.
        :param tlp: Traffic Light Protocol level.
        :param indicators: List of indicators (optional).
        :return: Created pulse data.
        """
        data = {
            "name": name,
            "description": description,
            "tlp": tlp
        }
        if indicators:
            data["indicators"] = indicators
        url = f"{self.base_url}pulses"
        response = requests.post(url, headers=self.headers, json=data)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Subscribe to a pulse.",
        name="subscribe_pulse"
    )
    def subscribe_pulse(
        self,
        pulse_id: str
    ) -> Dict[str, Any]:
        """
        Subscribes to a pulse.
        
        :param pulse_id: The pulse ID.
        :return: Subscription response.
        """
        url = f"{self.base_url}pulses/{pulse_id}/subscribe"
        response = requests.post(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Unsubscribe from a pulse.",
        name="unsubscribe_pulse"
    )
    def unsubscribe_pulse(
        self,
        pulse_id: str
    ) -> Dict[str, Any]:
        """
        Unsubscribes from a pulse.
        
        :param pulse_id: The pulse ID.
        :return: Unsubscription response.
        """
        url = f"{self.base_url}pulses/{pulse_id}/unsubscribe"
        response = requests.post(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    # Indicators Endpoints

    @kernel_function(
        description="Get general information for an IPv4 address.",
        name="get_ipv4_indicator"
    )
    def get_ipv4_indicator(
        self,
        ip: str,
        section: Optional[str] = "general"  # general, reputation, geo, malware, url_list, passive_dns, http_scans
    ) -> Dict[str, Any]:
        """
        Retrieves indicator data for an IPv4 address.
        
        :param ip: IPv4 address.
        :param section: Specific section (optional).
        :return: Dictionary containing indicator data.
        """
        url = f"{self.base_url}indicators/IPv4/{ip}/{section}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get general information for an IPv6 address.",
        name="get_ipv6_indicator"
    )
    def get_ipv6_indicator(
        self,
        ip: str,
        section: Optional[str] = "general"  # general, reputation, geo, malware, url_list, passive_dns
    ) -> Dict[str, Any]:
        """
        Retrieves indicator data for an IPv6 address.
        
        :param ip: IPv6 address.
        :param section: Specific section (optional).
        :return: Dictionary containing indicator data.
        """
        url = f"{self.base_url}indicators/IPv6/{ip}/{section}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get general information for a domain.",
        name="get_domain_indicator"
    )
    def get_domain_indicator(
        self,
        domain: str,
        section: Optional[str] = "general"  # general, reputation, geo, malware, url_list, passive_dns
    ) -> Dict[str, Any]:
        """
        Retrieves indicator data for a domain.
        
        :param domain: Domain name.
        :param section: Specific section (optional).
        :return: Dictionary containing indicator data.
        """
        url = f"{self.base_url}indicators/domain/{domain}/{section}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get general information for a hostname.",
        name="get_hostname_indicator"
    )
    def get_hostname_indicator(
        self,
        hostname: str,
        section: Optional[str] = "general"
    ) -> Dict[str, Any]:
        """
        Retrieves indicator data for a hostname.
        
        :param hostname: Hostname.
        :param section: Specific section (optional).
        :return: Dictionary containing indicator data.
        """
        url = f"{self.base_url}indicators/hostname/{hostname}/{section}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get general information for a URL.",
        name="get_url_indicator"
    )
    def get_url_indicator(
        self,
        url: str,
        section: Optional[str] = "general"  # general, url_list, reputation, malware, passive_dns
    ) -> Dict[str, Any]:
        """
        Retrieves indicator data for a URL.
        
        :param url: URL.
        :param section: Specific section (optional).
        :return: Dictionary containing indicator data.
        """
        url = f"{self.base_url}indicators/URL/{url}/{section}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get general information for an email address.",
        name="get_email_indicator"
    )
    def get_email_indicator(
        self,
        email: str,
        section: Optional[str] = "general"
    ) -> Dict[str, Any]:
        """
        Retrieves indicator data for an email.
        
        :param email: Email address.
        :param section: Specific section (optional).
        :return: Dictionary containing indicator data.
        """
        url = f"{self.base_url}indicators/email/{email}/{section}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get general information for a file hash.",
        name="get_file_indicator"
    )
    def get_file_indicator(
        self,
        file_hash: str,
        section: Optional[str] = "general"  # general, analysis, behavior, sandbox, yara, antivirus
    ) -> Dict[str, Any]:
        """
        Retrieves indicator data for a file hash (MD5/SHA1/SHA256).
        
        :param file_hash: File hash.
        :param section: Specific section (optional).
        :return: Dictionary containing indicator data.
        """
        url = f"{self.base_url}indicators/file/{file_hash}/{section}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get latest indicators.",
        name="get_latest_indicators"
    )
    def get_latest_indicators(
        self,
        limit: Optional[int] = 100
    ) -> Dict[str, Any]:
        """
        Retrieves the latest indicators.
        
        :param limit: Maximum number of indicators.
        :return: Dictionary containing latest indicators.
        """
        params = {"limit": limit}
        url = f"{self.base_url}indicators/latest"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Search for indicators by type and value.",
        name="search_indicators"
    )
    def search_indicators(
        self,
        indicator_type: str,  # IPv4, domain, URL, etc.
        value: str,
        limit: Optional[int] = 50
    ) -> Dict[str, Any]:
        """
        Searches for indicators.
        
        :param indicator_type: Type of indicator.
        :param value: Value to search.
        :param limit: Maximum number of results.
        :return: Dictionary containing search results.
        """
        params = {"type": indicator_type, "value": value, "limit": limit}
        url = f"{self.base_url}indicators"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    # Submission Endpoints (for Indicators)

    @kernel_function(
        description="Submit a file for analysis.",
        name="submit_file"
    )
    def submit_file(
        self,
        file_path: str,
        tlp: Optional[str] = "white"
    ) -> Dict[str, Any]:
        """
        Submits a file for analysis.
        
        :param file_path: Path to the file.
        :param tlp: TLP level.
        :return: Submission response.
        """
        url = f"{self.base_url}indicators"
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = {'tlp': tlp} if tlp else {}
            response = requests.post(url, headers={"X-OTX-API-KEY": self.api_key}, files=files, data=data)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Submit a single URL for analysis.",
        name="submit_url"
    )
    def submit_url(
        self,
        url: str,
        tlp: Optional[str] = "white"
    ) -> Dict[str, Any]:
        """
        Submits a URL for analysis.
        
        :param url: The URL.
        :param tlp: TLP level.
        :return: Submission response.
        """
        url_path = f"{self.base_url}indicators"
        data = {'url': url, 'tlp': tlp}
        response = requests.post(url_path, headers=self.headers, data=data)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Submit multiple URLs for analysis.",
        name="submit_urls"
    )
    def submit_urls(
        self,
        urls: List[str],
        tlp: Optional[str] = "white"
    ) -> Dict[str, Any]:
        """
        Submits multiple URLs for analysis.
        
        :param urls: List of URLs.
        :param tlp: TLP level.
        :return: Submission response.
        """
        url_path = f"{self.base_url}indicators"
        data = {'urls': '\n'.join(urls), 'tlp': tlp}
        response = requests.post(url_path, headers=self.headers, data=data)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="List submitted files.",
        name="list_submitted_files"
    )
    def list_submitted_files(
        self,
        limit: Optional[int] = 50
    ) -> Dict[str, Any]:
        """
        Lists user's submitted files.
        
        :param limit: Maximum number.
        :return: List of submissions.
        """
        params = {"limit": limit}
        url = f"{self.base_url}indicators"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="List submitted URLs.",
        name="list_submitted_urls"
    )
    def list_submitted_urls(
        self,
        limit: Optional[int] = 50
    ) -> Dict[str, Any]:
        """
        Lists user's submitted URLs.
        
        :param limit: Maximum number.
        :return: List of submissions.
        """
        params = {"limit": limit, "section": "url_list"}
        url = f"{self.base_url}indicators"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Update TLP for a submitted file.",
        name="update_file_tlp"
    )
    def update_file_tlp(
        self,
        file_hash: str,
        tlp: str
    ) -> Dict[str, Any]:
        """
        Updates TLP for a file.
        
        :param file_hash: File hash.
        :param tlp: New TLP.
        :return: Update response.
        """
        url = f"{self.base_url}indicators"
        data = {'file_hash': file_hash, 'tlp': tlp}
        response = requests.post(url, headers=self.headers, data=data)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Update TLP for a submitted URL.",
        name="update_url_tlp"
    )
    def update_url_tlp(
        self,
        url: str,
        tlp: str
    ) -> Dict[str, Any]:
        """
        Updates TLP for a URL.
        
        :param url: URL.
        :param tlp: New TLP.
        :return: Update response.
        """
        url_path = f"{self.base_url}indicators"
        data = {'url': url, 'tlp': tlp}
        response = requests.post(url_path, headers=self.headers, data=data)
        response.raise_for_status()
        return response.json()

    # Groups Endpoints

    @kernel_function(
        description="List groups.",
        name="list_groups"
    )
    def list_groups(
        self,
        limit: Optional[int] = 50,
        page: Optional[int] = 1
    ) -> Dict[str, Any]:
        """
        Lists available groups.
        
        :param limit: Maximum number of groups.
        :param page: Page number.
        :return: Dictionary containing group list.
        """
        params = {"limit": limit, "page": page}
        url = f"{self.base_url}groups"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get details for a group.",
        name="get_group"
    )
    def get_group(
        self,
        group_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves group details.
        
        :param group_id: Group ID.
        :return: Dictionary containing group data.
        """
        url = f"{self.base_url}groups/{group_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    # Collections Endpoints (if applicable, based on docs)

    @kernel_function(
        description="List collections.",
        name="list_collections"
    )
    def list_collections(
        self,
        limit: Optional[int] = 50
    ) -> Dict[str, Any]:
        """
        Lists user's collections.
        
        :param limit: Maximum number.
        :return: Dictionary containing collections.
        """
        params = {"limit": limit}
        url = f"{self.base_url}collections"
        response = requests.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

# Example usage with Semantic Kernel:
# from semantic_kernel import Kernel
# kernel = Kernel()
# api_key = "your_otx_api_key"
# otx_skill = OtxPlugin(api_key)
# kernel.add_skill(otx_skill, skill_name="OTX")
# result = await kernel.invoke("OTX", "get_ipv4_indicator", ip="8.8.8.8")
# print(result)