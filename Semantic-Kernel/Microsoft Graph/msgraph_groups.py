from typing import Annotated, Any, Dict, List
import json

from semantic_kernel.functions import kernel_function
from msgraph import GraphServiceClient
from msgraph.generated.models.group import Group
from msgraph.generated.models.reference_create import ReferenceCreate
from msgraph.generated.models.user import User
from msgraph.generated.models.directory_object import DirectoryObject

# Import request builders for pagination support
from msgraph.generated.groups.groups_request_builder import GroupsRequestBuilder
from msgraph.generated.groups.item.members.members_request_builder import MembersRequestBuilder
from msgraph.generated.groups.item.owners.owners_request_builder import OwnersRequestBuilder

class MicrosoftGraphGroups:
    """
    A Semantic Kernel plugin for interacting with Microsoft Graph Groups APIs.
    This plugin provides functions to manage and retrieve group data using the Microsoft Graph SDK.
    """

    def __init__(self, graph_client: GraphServiceClient):
        self._client = graph_client

    @kernel_function(
        name="create_group",
        description="Creates a new group. Provide group details as a JSON string of properties."
    )
    async def create_group(
        self,
        group_details: Annotated[str, "JSON string of group properties to create (e.g., {'displayName': 'New Group', 'mailEnabled': false, 'securityEnabled': true, 'groupTypes': []})."]
    ) -> str:
        """Creates a new group."""
        details_dict = json.loads(group_details)
        group = Group(**details_dict)
        result = await self._client.groups.post(group)
        if result:
            return json.dumps(result.__dict__)
        return json.dumps({"error": "Group creation failed"})

    @kernel_function(
        name="list_groups",
        description="Lists groups in the organization."
    )
    async def list_groups(
        self,
        top: Annotated[int, "Number of items to return per page."] = None,
        skiptoken: Annotated[str, "The skip token for pagination."] = None
    ) -> str:
        """Lists groups in the organization."""
        request_config = GroupsRequestBuilder.GroupsRequestBuilderGetRequestConfiguration()
        if top:
            request_config.query_parameters.top = top
        if skiptoken:
            request_config.query_parameters.skiptoken = skiptoken
        groups_page = await self._client.groups.get(request_configuration=request_config)
        result = {
            "value": [group.__dict__ for group in groups_page.value] if groups_page and groups_page.value else [],
            "next_link": groups_page.odata_next_link if groups_page else None
        }
        return json.dumps(result)

    @kernel_function(
        name="get_group",
        description="Gets a specific group by ID."
    )
    async def get_group(
        self,
        group_id: Annotated[str, "The ID of the group."]
    ) -> str:
        """Gets a specific group by ID."""
        group = await self._client.groups.by_group_id(group_id).get()
        if group:
            return json.dumps(group.__dict__)
        return json.dumps({"error": "Group not found"})

    @kernel_function(
        name="update_group",
        description="Updates a group's properties. Provide updates as a JSON string of properties."
    )
    async def update_group(
        self,
        group_id: Annotated[str, "The ID of the group."],
        updates: Annotated[str, "JSON string of properties to update (e.g., {'displayName': 'Updated Group'})."]
    ) -> str:
        """Updates a group's properties."""
        update_dict = json.loads(updates)
        group = Group(**update_dict)
        await self._client.groups.by_group_id(group_id).patch(group)
        return json.dumps({"success": True})

    @kernel_function(
        name="delete_group",
        description="Deletes a group by ID."
    )
    async def delete_group(
        self,
        group_id: Annotated[str, "The ID of the group."]
    ) -> str:
        """Deletes a group by ID."""
        await self._client.groups.by_group_id(group_id).delete()
        return json.dumps({"success": True})

    @kernel_function(
        name="list_members",
        description="Lists members of a group."
    )
    async def list_members(
        self,
        group_id: Annotated[str, "The ID of the group."],
        top: Annotated[int, "Number of items to return per page."] = None,
        skiptoken: Annotated[str, "The skip token for pagination."] = None
    ) -> str:
        """Lists members of a group."""
        request_config = MembersRequestBuilder.MembersRequestBuilderGetRequestConfiguration()
        if top:
            request_config.query_parameters.top = top
        if skiptoken:
            request_config.query_parameters.skiptoken = skiptoken
        members_page = await self._client.groups.by_group_id(group_id).members.get(request_configuration=request_config)
        result = {
            "value": [member.__dict__ for member in members_page.value] if members_page and members_page.value else [],
            "next_link": members_page.odata_next_link if members_page else None
        }
        return json.dumps(result)

    @kernel_function(
        name="add_member",
        description="Adds a member to a group."
    )
    async def add_member(
        self,
        group_id: Annotated[str, "The ID of the group."],
        member_id: Annotated[str, "The ID of the member (user, group, device, etc.) to add."]
    ) -> str:
        """Adds a member to a group."""
        ref = ReferenceCreate()
        ref.odata_id = f"https://graph.microsoft.com/v1.0/directoryObjects/{member_id}"
        await self._client.groups.by_group_id(group_id).members.ref.post(ref)
        return json.dumps({"success": True})

    @kernel_function(
        name="remove_member",
        description="Removes a member from a group."
    )
    async def remove_member(
        self,
        group_id: Annotated[str, "The ID of the group."],
        member_id: Annotated[str, "The ID of the member to remove."]
    ) -> str:
        """Removes a member from a group."""
        await self._client.groups.by_group_id(group_id).members.by_directory_object_id(member_id).ref.delete()
        return json.dumps({"success": True})

    @kernel_function(
        name="list_owners",
        description="Lists owners of a group."
    )
    async def list_owners(
        self,
        group_id: Annotated[str, "The ID of the group."],
        top: Annotated[int, "Number of items to return per page."] = None,
        skiptoken: Annotated[str, "The skip token for pagination."] = None
    ) -> str:
        """Lists owners of a group."""
        request_config = OwnersRequestBuilder.OwnersRequestBuilderGetRequestConfiguration()
        if top:
            request_config.query_parameters.top = top
        if skiptoken:
            request_config.query_parameters.skiptoken = skiptoken
        owners_page = await self._client.groups.by_group_id(group_id).owners.get(request_configuration=request_config)
        result = {
            "value": [owner.__dict__ for owner in owners_page.value] if owners_page and owners_page.value else [],
            "next_link": owners_page.odata_next_link if owners_page else None
        }
        return json.dumps(result)

    @kernel_function(
        name="add_owner",
        description="Adds an owner to a group."
    )
    async def add_owner(
        self,
        group_id: Annotated[str, "The ID of the group."],
        owner_id: Annotated[str, "The ID of the owner (user or service principal) to add."]
    ) -> str:
        """Adds an owner to a group."""
        ref = ReferenceCreate()
        ref.odata_id = f"https://graph.microsoft.com/v1.0/directoryObjects/{owner_id}"
        await self._client.groups.by_group_id(group_id).owners.ref.post(ref)
        return json.dumps({"success": True})

    @kernel_function(
        name="remove_owner",
        description="Removes an owner from a group."
    )
    async def remove_owner(
        self,
        group_id: Annotated[str, "The ID of the group."],
        owner_id: Annotated[str, "The ID of the owner to remove."]
    ) -> str:
        """Removes an owner from a group."""
        await self._client.groups.by_group_id(group_id).owners.by_directory_object_id(owner_id).ref.delete()
        return json.dumps({"success": True})