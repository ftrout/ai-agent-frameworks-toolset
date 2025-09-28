import hashlib
import json
import requests
from typing import Dict, Any, Optional, List

from semantic_kernel.skill_definition import kernel_function

class VirusTotalPlugin:
    """
    A Semantic Kernel plugin for interacting with the VirusTotal API v3.
    This plugin provides functions for all major endpoints, including public and premium features.
    
    Note: Some endpoints require a premium (Enterprise) API key. Public API has rate limits (e.g., 4 req/min).
    For binary responses (e.g., downloads), functions return bytes or URLs where applicable.
    """

    def __init__(self, api_key: str):
        """
        Initialize the VirusTotal plugin.
        
        :param api_key: Your VirusTotal API key (obtain from https://www.virustotal.com/gui/my/apikey).
        """
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3/"
        self.headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"  # For POST/PATCH with JSON
        }

    # Files Endpoints

    @kernel_function(
        description="Upload a file for scanning (up to 32MB for public, larger for premium) and returns the analysis ID. Use get_analysis to retrieve results.",
        name="upload_file"
    )
    def upload_file(
        self,
        file_path: str
    ) -> str:
        """
        Uploads a file to VirusTotal for scanning.
        
        :param file_path: Path to the file to upload.
        :return: Analysis ID for polling the scan results.
        """
        url = f"{self.base_url}files"
        with open(file_path, 'rb') as f:
            files = {'file': (file_path, f)}
            response = requests.post(url, headers={"x-apikey": self.api_key}, files=files)
        response.raise_for_status()
        return response.json()["data"]["id"]

    @kernel_function(
        description="Get a presigned upload URL for large files (premium required).",
        name="get_large_file_upload_url"
    )
    def get_large_file_upload_url(self) -> str:
        """
        Retrieves a presigned URL for uploading large files.
        
        :return: Presigned upload URL.
        """
        url = f"{self.base_url}files/upload_url"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get a file report by its hash (MD5, SHA1, or SHA256).",
        name="get_file_report"
    )
    def get_file_report(
        self,
        hash_value: str
    ) -> Dict[str, Any]:
        """
        Retrieves a file report from VirusTotal.
        
        :param hash_value: The hash of the file (MD5, SHA1, or SHA256).
        :return: Dictionary containing the file report data.
        """
        url = f"{self.base_url}files/{hash_value}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Re-analyze a file by its hash.",
        name="reanalyze_file"
    )
    def reanalyze_file(
        self,
        hash_value: str
    ) -> str:
        """
        Triggers a re-scan of an existing file.
        
        :param hash_value: The hash of the file.
        :return: Analysis ID.
        """
        url = f"{self.base_url}files/{hash_value}/analyse"
        response = requests.post(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]["id"]

    @kernel_function(
        description="Add a comment to a file by its hash.",
        name="add_file_comment"
    )
    def add_file_comment(
        self,
        hash_value: str,
        comment: str
    ) -> Dict[str, Any]:
        """
        Adds a comment to a file.
        
        :param hash_value: The hash of the file.
        :param comment: The comment text.
        :return: Comment data.
        """
        url = f"{self.base_url}files/{hash_value}/comments"
        data = {"data": {"type": "comment", "attributes": {"text": comment}}}
        response = requests.post(url, headers=self.headers, data=json.dumps(data))
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get comments for a file by its hash.",
        name="get_file_comments"
    )
    def get_file_comments(
        self,
        hash_value: str,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Retrieves comments for a file.
        
        :param hash_value: The hash of the file.
        :param limit: Number of comments to return (optional).
        :return: List of comment data.
        """
        url = f"{self.base_url}files/{hash_value}/comments?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Add a vote to a file by its hash (verdict: 'malicious' or 'harmless').",
        name="add_file_vote"
    )
    def add_file_vote(
        self,
        hash_value: str,
        verdict: str
    ) -> Dict[str, Any]:
        """
        Adds a vote to a file.
        
        :param hash_value: The hash of the file.
        :param verdict: 'malicious' or 'harmless'.
        :return: Vote data.
        """
        url = f"{self.base_url}files/{hash_value}/votes"
        data = {"data": {"type": "vote", "attributes": {"verdict": verdict}}}
        response = requests.post(url, headers=self.headers, data=json.dumps(data))
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get votes for a file by its hash.",
        name="get_file_votes"
    )
    def get_file_votes(
        self,
        hash_value: str,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Retrieves votes for a file.
        
        :param hash_value: The hash of the file.
        :param limit: Number of votes to return (optional).
        :return: List of vote data.
        """
        url = f"{self.base_url}files/{hash_value}/votes?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Download a file by its hash (premium required for most files). Returns file bytes.",
        name="download_file"
    )
    def download_file(
        self,
        hash_value: str
    ) -> bytes:
        """
        Downloads a file from VirusTotal.
        
        :param hash_value: The hash of the file.
        :return: File content as bytes.
        """
        url = f"{self.base_url}files/{hash_value}/download"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.content

    @kernel_function(
        description="Get relationships for a file (e.g., 'analyses', 'behaviours', 'bundled_files', etc.).",
        name="get_file_relationship"
    )
    def get_file_relationship(
        self,
        hash_value: str,
        relationship: str,
        limit: Optional[int] = 10
    ) -> Dict[str, Any]:
        """
        Retrieves related objects for a file.
        
        :param hash_value: The hash of the file.
        :param relationship: The relationship type (e.g., 'analyses', 'behaviours').
        :param limit: Number of items to return (optional).
        :return: Relationship data.
        """
        url = f"{self.base_url}files/{hash_value}/relationships/{relationship}?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    # URLs Endpoints

    @kernel_function(
        description="Scan a URL and returns the analysis ID. Use get_analysis to retrieve results.",
        name="scan_url"
    )
    def scan_url(
        self,
        url_str: str
    ) -> str:
        """
        Submits a URL for scanning.
        
        :param url_str: The URL to scan.
        :return: Analysis ID for polling the scan results.
        """
        url = f"{self.base_url}urls"
        data = {'url': url_str}
        response = requests.post(url, headers=self.headers, data=data)
        response.raise_for_status()
        return response.json()["data"]["id"]

    @kernel_function(
        description="Get a URL report by the URL string (uses SHA256 prefix as ID).",
        name="get_url_report"
    )
    def get_url_report(
        self,
        url_str: str
    ) -> Dict[str, Any]:
        """
        Retrieves a URL report from VirusTotal.
        
        :param url_str: The URL to retrieve the report for.
        :return: Dictionary containing the URL report data.
        """
        url_id = hashlib.sha256(url_str.encode('utf-8')).hexdigest()
        url = f"{self.base_url}urls/{url_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Add a vote to a URL (verdict: 'malicious' or 'harmless').",
        name="add_url_vote"
    )
    def add_url_vote(
        self,
        url_str: str,
        verdict: str
    ) -> Dict[str, Any]:
        """
        Adds a vote to a URL.
        
        :param url_str: The URL.
        :param verdict: 'malicious' or 'harmless'.
        :return: Vote data.
        """
        url_id = hashlib.sha256(url_str.encode('utf-8')).hexdigest()
        url = f"{self.base_url}urls/{url_id}/votes"
        data = {"data": {"type": "vote", "attributes": {"verdict": verdict}}}
        response = requests.post(url, headers=self.headers, data=json.dumps(data))
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get votes for a URL.",
        name="get_url_votes"
    )
    def get_url_votes(
        self,
        url_str: str,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Retrieves votes for a URL.
        
        :param url_str: The URL.
        :param limit: Number of votes to return (optional).
        :return: List of vote data.
        """
        url_id = hashlib.sha256(url_str.encode('utf-8')).hexdigest()
        url = f"{self.base_url}urls/{url_id}/votes?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get relationships for a URL (e.g., 'analyses', 'downloaded_files').",
        name="get_url_relationship"
    )
    def get_url_relationship(
        self,
        url_str: str,
        relationship: str,
        limit: Optional[int] = 10
    ) -> Dict[str, Any]:
        """
        Retrieves related objects for a URL.
        
        :param url_str: The URL.
        :param relationship: The relationship type.
        :param limit: Number of items to return (optional).
        :return: Relationship data.
        """
        url_id = hashlib.sha256(url_str.encode('utf-8')).hexdigest()
        url = f"{self.base_url}urls/{url_id}/relationships/{relationship}?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get network location details for a URL.",
        name="get_url_network_location"
    )
    def get_url_network_location(
        self,
        url_str: str
    ) -> Dict[str, Any]:
        """
        Retrieves network details for a URL.
        
        :param url_str: The URL.
        :return: Network location data.
        """
        url_id = hashlib.sha256(url_str.encode('utf-8')).hexdigest()
        url = f"{self.base_url}urls/{url_id}/network_location"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    # Domains Endpoints

    @kernel_function(
        description="Get a domain report.",
        name="get_domain_report"
    )
    def get_domain_report(
        self,
        domain: str
    ) -> Dict[str, Any]:
        """
        Retrieves a domain report from VirusTotal.
        
        :param domain: The domain name.
        :return: Dictionary containing the domain report data.
        """
        url = f"{self.base_url}domains/{domain}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Add a vote to a domain (verdict: 'malicious' or 'harmless').",
        name="add_domain_vote"
    )
    def add_domain_vote(
        self,
        domain: str,
        verdict: str
    ) -> Dict[str, Any]:
        """
        Adds a vote to a domain.
        
        :param domain: The domain.
        :param verdict: 'malicious' or 'harmless'.
        :return: Vote data.
        """
        url = f"{self.base_url}domains/{domain}/votes"
        data = {"data": {"type": "vote", "attributes": {"verdict": verdict}}}
        response = requests.post(url, headers=self.headers, data=json.dumps(data))
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get votes for a domain.",
        name="get_domain_votes"
    )
    def get_domain_votes(
        self,
        domain: str,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Retrieves votes for a domain.
        
        :param domain: The domain.
        :param limit: Number of votes to return (optional).
        :return: List of vote data.
        """
        url = f"{self.base_url}domains/{domain}/votes?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get relationships for a domain (e.g., 'communicating_files', 'subdomains').",
        name="get_domain_relationship"
    )
    def get_domain_relationship(
        self,
        domain: str,
        relationship: str,
        limit: Optional[int] = 10
    ) -> Dict[str, Any]:
        """
        Retrieves related objects for a domain.
        
        :param domain: The domain.
        :param relationship: The relationship type.
        :param limit: Number of items to return (optional).
        :return: Relationship data.
        """
        url = f"{self.base_url}domains/{domain}/relationships/{relationship}?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    # IP Addresses Endpoints

    @kernel_function(
        description="Get an IP address report.",
        name="get_ip_report"
    )
    def get_ip_report(
        self,
        ip: str
    ) -> Dict[str, Any]:
        """
        Retrieves an IP address report from VirusTotal.
        
        :param ip: The IP address (IPv4 or IPv6).
        :return: Dictionary containing the IP report data.
        """
        url = f"{self.base_url}ip_addresses/{ip}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Add a vote to an IP (verdict: 'malicious' or 'harmless').",
        name="add_ip_vote"
    )
    def add_ip_vote(
        self,
        ip: str,
        verdict: str
    ) -> Dict[str, Any]:
        """
        Adds a vote to an IP.
        
        :param ip: The IP.
        :param verdict: 'malicious' or 'harmless'.
        :return: Vote data.
        """
        url = f"{self.base_url}ip_addresses/{ip}/votes"
        data = {"data": {"type": "vote", "attributes": {"verdict": verdict}}}
        response = requests.post(url, headers=self.headers, data=json.dumps(data))
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get votes for an IP.",
        name="get_ip_votes"
    )
    def get_ip_votes(
        self,
        ip: str,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Retrieves votes for an IP.
        
        :param ip: The IP.
        :param limit: Number of votes to return (optional).
        :return: List of vote data.
        """
        url = f"{self.base_url}ip_addresses/{ip}/votes?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get relationships for an IP (e.g., 'communicating_files', 'resolutions').",
        name="get_ip_relationship"
    )
    def get_ip_relationship(
        self,
        ip: str,
        relationship: str,
        limit: Optional[int] = 10
    ) -> Dict[str, Any]:
        """
        Retrieves related objects for an IP.
        
        :param ip: The IP.
        :param relationship: The relationship type.
        :param limit: Number of items to return (optional).
        :return: Relationship data.
        """
        url = f"{self.base_url}ip_addresses/{ip}/relationships/{relationship}?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    # Analyses Endpoints

    @kernel_function(
        description="Get analysis status by ID (for file or URL scans).",
        name="get_analysis"
    )
    def get_analysis(
        self,
        analysis_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves the status and results of an analysis.
        
        :param analysis_id: The analysis ID from upload_file or scan_url.
        :return: Dictionary containing the analysis data.
        """
        url = f"{self.base_url}analyses/{analysis_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    # Intelligence & Search Endpoints

    @kernel_function(
        description="Perform an advanced intelligence search (premium; query supports VTI syntax).",
        name="intelligence_search"
    )
    def intelligence_search(
        self,
        query: str,
        limit: Optional[int] = 10
    ) -> Dict[str, Any]:
        """
        Searches across IoCs using VirusTotal Intelligence.
        
        :param query: Search query (e.g., 'type:peexe engines:>5').
        :param limit: Number of results (optional).
        :return: Search results.
        """
        url = f"{self.base_url}intelligence/search?query={query}&limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get a minutely file feed batch (premium; time in YYYYMMDDhhmm).",
        name="get_file_feed"
    )
    def get_file_feed(
        self,
        time: str
    ) -> bytes:
        """
        Retrieves a file feed batch.
        
        :param time: Timestamp in YYYYMMDDhhmm format.
        :return: Feed data as bytes (zip file).
        """
        url = f"{self.base_url}intelligence/feeds/files/{time}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.content

    @kernel_function(
        description="Get a minutely URL feed batch (premium; time in YYYYMMDDhhmm).",
        name="get_url_feed"
    )
    def get_url_feed(
        self,
        time: str
    ) -> bytes:
        """
        Retrieves a URL feed batch.
        
        :param time: Timestamp in YYYYMMDDhhmm format.
        :return: Feed data as bytes (zip file).
        """
        url = f"{self.base_url}intelligence/feeds/urls/{time}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.content

    # Collections Endpoints (Premium)

    @kernel_function(
        description="Create a new collection (premium; data as JSON string for attributes).",
        name="create_collection"
    )
    def create_collection(
        self,
        data_json: str
    ) -> Dict[str, Any]:
        """
        Creates a new collection.
        
        :param data_json: JSON string for collection data (e.g., '{"data": {"type": "collection", "attributes": {...}}}').
        :return: Collection data.
        """
        url = f"{self.base_url}collections"
        response = requests.post(url, headers=self.headers, data=data_json)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get a collection by ID (premium).",
        name="get_collection"
    )
    def get_collection(
        self,
        collection_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves a collection.
        
        :param collection_id: The collection ID.
        :return: Collection data.
        """
        url = f"{self.base_url}collections/{collection_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get relationships for a collection (premium).",
        name="get_collection_relationship"
    )
    def get_collection_relationship(
        self,
        collection_id: str,
        relationship: str,
        limit: Optional[int] = 10
    ) -> Dict[str, Any]:
        """
        Retrieves related objects for a collection.
        
        :param collection_id: The collection ID.
        :param relationship: The relationship type.
        :param limit: Number of items to return (optional).
        :return: Relationship data.
        """
        url = f"{self.base_url}collections/{collection_id}/{relationship}?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    # Threat Actors Endpoints (Premium)

    @kernel_function(
        description="List threat actors (premium).",
        name="list_threat_actors"
    )
    def list_threat_actors(
        self,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Lists threat actors.
        
        :param limit: Number of actors to return (optional).
        :return: List of threat actor data.
        """
        url = f"{self.base_url}threat_actors?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get a specific threat actor by ID (premium).",
        name="get_threat_actor"
    )
    def get_threat_actor(
        self,
        actor_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves a threat actor.
        
        :param actor_id: The threat actor ID.
        :return: Threat actor data.
        """
        url = f"{self.base_url}threat_actors/{actor_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    # Users & Groups Endpoints (Premium)

    @kernel_function(
        description="Get user information by ID (premium).",
        name="get_user"
    )
    def get_user(
        self,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves user information.
        
        :param user_id: The user ID or username.
        :return: User data.
        """
        url = f"{self.base_url}users/{user_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get group information by ID (premium).",
        name="get_group"
    )
    def get_group(
        self,
        group_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves group information.
        
        :param group_id: The group ID.
        :return: Group data.
        """
        url = f"{self.base_url}groups/{group_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="List group members (premium).",
        name="list_group_members"
    )
    def list_group_members(
        self,
        group_id: str,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Lists members of a group.
        
        :param group_id: The group ID.
        :param limit: Number of members to return (optional).
        :return: List of member data.
        """
        url = f"{self.base_url}groups/{group_id}/members?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    # Livehunt Endpoints (Premium)

    @kernel_function(
        description="List Livehunt rulesets (premium).",
        name="list_livehunt_rulesets"
    )
    def list_livehunt_rulesets(
        self,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Lists Livehunt rulesets.
        
        :param limit: Number of rulesets to return (optional).
        :return: List of ruleset data.
        """
        url = f"{self.base_url}livehunts/rulesets?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get a Livehunt ruleset by ID (premium).",
        name="get_livehunt_ruleset"
    )
    def get_livehunt_ruleset(
        self,
        ruleset_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves a Livehunt ruleset.
        
        :param ruleset_id: The ruleset ID.
        :return: Ruleset data.
        """
        url = f"{self.base_url}livehunts/rulesets/{ruleset_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Create a new Livehunt ruleset (premium; data as JSON string).",
        name="create_livehunt_ruleset"
    )
    def create_livehunt_ruleset(
        self,
        data_json: str
    ) -> Dict[str, Any]:
        """
        Creates a new Livehunt ruleset.
        
        :param data_json: JSON string for ruleset data.
        :return: Ruleset data.
        """
        url = f"{self.base_url}livehunts/rulesets"
        response = requests.post(url, headers=self.headers, data=data_json)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Update a Livehunt ruleset (premium; data as JSON string).",
        name="update_livehunt_ruleset"
    )
    def update_livehunt_ruleset(
        self,
        ruleset_id: str,
        data_json: str
    ) -> Dict[str, Any]:
        """
        Updates a Livehunt ruleset.
        
        :param ruleset_id: The ruleset ID.
        :param data_json: JSON string for updates.
        :return: Updated ruleset data.
        """
        url = f"{self.base_url}livehunts/rulesets/{ruleset_id}"
        response = requests.patch(url, headers=self.headers, data=data_json)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Delete a Livehunt ruleset (premium).",
        name="delete_livehunt_ruleset"
    )
    def delete_livehunt_ruleset(
        self,
        ruleset_id: str
    ) -> None:
        """
        Deletes a Livehunt ruleset.
        
        :param ruleset_id: The ruleset ID.
        """
        url = f"{self.base_url}livehunts/rulesets/{ruleset_id}"
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()

    @kernel_function(
        description="Get Livehunt notifications (premium).",
        name="get_livehunt_notifications"
    )
    def get_livehunt_notifications(
        self,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Retrieves Livehunt notifications.
        
        :param limit: Number of notifications to return (optional).
        :return: List of notification data.
        """
        url = f"{self.base_url}livehunts/notifications?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    # Retrohunt Endpoints (Premium)

    @kernel_function(
        description="List Retrohunt jobs (premium).",
        name="list_retrohunt_jobs"
    )
    def list_retrohunt_jobs(
        self,
        limit: Optional[int] = 10
    ) -> List[Dict[str, Any]]:
        """
        Lists Retrohunt jobs.
        
        :param limit: Number of jobs to return (optional).
        :return: List of job data.
        """
        url = f"{self.base_url}retrohunts?limit={limit}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Get a Retrohunt job by ID (premium).",
        name="get_retrohunt_job"
    )
    def get_retrohunt_job(
        self,
        job_id: str
    ) -> Dict[str, Any]:
        """
        Retrieves a Retrohunt job.
        
        :param job_id: The job ID.
        :return: Job data.
        """
        url = f"{self.base_url}retrohunts/{job_id}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Create a new Retrohunt job (premium; data as JSON string).",
        name="create_retrohunt_job"
    )
    def create_retrohunt_job(
        self,
        data_json: str
    ) -> Dict[str, Any]:
        """
        Creates a new Retrohunt job.
        
        :param data_json: JSON string for job data.
        :return: Job data.
        """
        url = f"{self.base_url}retrohunts"
        response = requests.post(url, headers=self.headers, data=data_json)
        response.raise_for_status()
        return response.json()["data"]

    @kernel_function(
        description="Delete a Retrohunt job (premium).",
        name="delete_retrohunt_job"
    )
    def delete_retrohunt_job(
        self,
        job_id: str
    ) -> None:
        """
        Deletes a Retrohunt job.
        
        :param job_id: The job ID.
        """
        url = f"{self.base_url}retrohunts/{job_id}"
        response = requests.delete(url, headers=self.headers)
        response.raise_for_status()

    @kernel_function(
        description="Abort a running Retrohunt job (premium).",
        name="abort_retrohunt_job"
    )
    def abort_retrohunt_job(
        self,
        job_id: str
    ) -> None:
        """
        Aborts a Retrohunt job.
        
        :param job_id: The job ID.
        """
        url = f"{self.base_url}retrohunts/{job_id}/abort"
        response = requests.post(url, headers=self.headers)
        response.raise_for_status()

    # Feeds Endpoints (Premium, Hourly)

    @kernel_function(
        description="Get hourly file feed batch (premium; time in YYYYMMDDhh).",
        name="get_hourly_file_feed"
    )
    def get_hourly_file_feed(
        self,
        time: str
    ) -> bytes:
        """
        Retrieves an hourly file feed batch.
        
        :param time: Timestamp in YYYYMMDDhh format.
        :return: Feed data as bytes.
        """
        url = f"{self.base_url}feeds/files/{time}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.content

    @kernel_function(
        description="Get hourly file behaviors feed batch (premium; time in YYYYMMDDhh).",
        name="get_hourly_file_behaviors_feed"
    )
    def get_hourly_file_behaviors_feed(
        self,
        time: str
    ) -> bytes:
        """
        Retrieves an hourly file behaviors feed batch.
        
        :param time: Timestamp in YYYYMMDDhh format.
        :return: Feed data as bytes.
        """
        url = f"{self.base_url}feeds/files_behaviours/{time}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.content

    @kernel_function(
        description="Get hourly URL feed batch (premium; time in YYYYMMDDhh).",
        name="get_hourly_url_feed"
    )
    def get_hourly_url_feed(
        self,
        time: str
    ) -> bytes:
        """
        Retrieves an hourly URL feed batch.
        
        :param time: Timestamp in YYYYMMDDhh format.
        :return: Feed data as bytes.
        """
        url = f"{self.base_url}feeds/urls/{time}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.content

    # Graph Endpoints (Premium)

    @kernel_function(
        description="Add a relationship to the graph (premium; user_key is your graph key, data as JSON string).",
        name="add_graph_relationship"
    )
    def add_graph_relationship(
        self,
        user_key: str,
        data_json: str
    ) -> Dict[str, Any]:
        """
        Adds a relationship to the graph.
        
        :param user_key: Your graph user key.
        :param data_json: JSON string for relationship data.
        :return: Response data.
        """
        url = f"{self.base_url}graph/{user_key}"
        response = requests.post(url, headers=self.headers, data=data_json)
        response.raise_for_status()
        return response.json()

    # Other Utility Endpoints

    @kernel_function(
        description="Simple search across IoCs and comments.",
        name="simple_search"
    )
    def simple_search(
        self,
        query: str
    ) -> Dict[str, Any]:
        """
        Performs a simple search.
        
        :param query: Search query.
        :return: Search results.
        """
        url = f"{self.base_url}api/search?query={query}"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()

    @kernel_function(
        description="Get current user's API usage and quotas.",
        name="get_current_user"
    )
    def get_current_user(self) -> Dict[str, Any]:
        """
        Retrieves current user information.
        
        :return: User data.
        """
        url = f"{self.base_url}users/me"
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        return response.json()["data"]

# Example usage with Semantic Kernel:
# from semantic_kernel import Kernel
# kernel = Kernel()
# api_key = "your_virustotal_api_key"
# vt_skill = VirusTotalPlugin(api_key)
# kernel.add_skill(vt_skill, skill_name="VirusTotal")
# result = await kernel.invoke("VirusTotal", "get_file_report", hash_value="your_file_hash")
# print(result)