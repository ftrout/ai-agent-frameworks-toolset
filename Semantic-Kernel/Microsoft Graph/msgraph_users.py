from typing import Annotated, Any, Dict, List
import json

from semantic_kernel.functions import kernel_function
from msgraph import GraphServiceClient
from msgraph.generated.models.user import User
from msgraph.generated.models.invitation import Invitation
from msgraph.generated.models.reference_create import ReferenceCreate
from msgraph.generated.models.password_profile import PasswordProfile
from msgraph.generated.models.change_password_request_body import ChangePasswordRequestBody
from msgraph.generated.models.drive import Drive
from msgraph.generated.models.event import Event
from msgraph.generated.models.group import Group
from msgraph.generated.models.message import Message
from msgraph.generated.models.team import Team

# Import request builders for pagination support
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from msgraph.generated.users.item.messages.messages_request_builder import MessagesRequestBuilder
from msgraph.generated.users.item.events.events_request_builder import EventsRequestBuilder
from msgraph.generated.users.item.member_of.member_of_request_builder import MemberOfRequestBuilder
from msgraph.generated.users.item.joined_teams.joined_teams_request_builder import JoinedTeamsRequestBuilder

class MicrosoftGraphUsers:
    """
    A Semantic Kernel plugin for interacting with Microsoft Graph Users APIs.
    This plugin provides functions to manage and retrieve user data using the Microsoft Graph SDK.
    """

    def __init__(self, graph_client: GraphServiceClient):
        self._client = graph_client

    @kernel_function(
        name="get_me",
        description="Gets the details of the signed-in user."
    )
    async def get_me(self) -> str:
        """Gets the details of the signed-in user."""
        user = await self._client.me.get()
        if user:
            return json.dumps(user.__dict__)
        return json.dumps({"error": "User not found"})

    @kernel_function(
        name="list_users",
        description="Lists users in the organization."
    )
    async def list_users(
        self,
        top: Annotated[int, "Number of items to return per page."] = None,
        skiptoken: Annotated[str, "The skip token for pagination."] = None
    ) -> str:
        """Lists users in the organization."""
        request_config = UsersRequestBuilder.UsersRequestBuilderGetRequestConfiguration()
        if top:
            request_config.query_parameters.top = top
        if skiptoken:
            request_config.query_parameters.skiptoken = skiptoken
        users_page = await self._client.users.get(request_configuration=request_config)
        result = {
            "value": [user.__dict__ for user in users_page.value] if users_page and users_page.value else [],
            "next_link": users_page.odata_next_link if users_page else None
        }
        return json.dumps(result)

    @kernel_function(
        name="get_user",
        description="Gets a specific user by ID or userPrincipalName."
    )
    async def get_user(
        self,
        user_id: Annotated[str, "The ID or userPrincipalName of the user."]
    ) -> str:
        """Gets a specific user by ID or userPrincipalName."""
        user = await self._client.users.by_user_id(user_id).get()
        if user:
            return json.dumps(user.__dict__)
        return json.dumps({"error": "User not found"})

    @kernel_function(
        name="get_manager",
        description="Gets the manager of a specific user."
    )
    async def get_manager(
        self,
        user_id: Annotated[str, "The ID or userPrincipalName of the user."]
    ) -> str:
        """Gets the manager of a specific user."""
        manager = await self._client.users.by_user_id(user_id).manager.get()
        if manager:
            return json.dumps(manager.__dict__)
        return json.dumps({"error": "Manager not found"})

    @kernel_function(
        name="list_messages",
        description="Lists the user's email messages in their primary inbox."
    )
    async def list_messages(
        self,
        user_id: Annotated[str, "The ID or userPrincipalName of the user."],
        top: Annotated[int, "Number of items to return per page."] = None,
        skiptoken: Annotated[str, "The skip token for pagination."] = None
    ) -> str:
        """Lists the user's email messages in their primary inbox."""
        request_config = MessagesRequestBuilder.MessagesRequestBuilderGetRequestConfiguration()
        if top:
            request_config.query_parameters.top = top
        if skiptoken:
            request_config.query_parameters.skiptoken = skiptoken
        messages_page = await self._client.users.by_user_id(user_id).messages.get(request_configuration=request_config)
        result = {
            "value": [msg.__dict__ for msg in messages_page.value] if messages_page and messages_page.value else [],
            "next_link": messages_page.odata_next_link if messages_page else None
        }
        return json.dumps(result)

    @kernel_function(
        name="list_events",
        description="Lists the user's upcoming events in their calendar."
    )
    async def list_events(
        self,
        user_id: Annotated[str, "The ID or userPrincipalName of the user."],
        top: Annotated[int, "Number of items to return per page."] = None,
        skiptoken: Annotated[str, "The skip token for pagination."] = None
    ) -> str:
        """Lists the user's upcoming events in their calendar."""
        request_config = EventsRequestBuilder.EventsRequestBuilderGetRequestConfiguration()
        if top:
            request_config.query_parameters.top = top
        if skiptoken:
            request_config.query_parameters.skiptoken = skiptoken
        events_page = await self._client.users.by_user_id(user_id).events.get(request_configuration=request_config)
        result = {
            "value": [event.__dict__ for event in events_page.value] if events_page and events_page.value else [],
            "next_link": events_page.odata_next_link if events_page else None
        }
        return json.dumps(result)

    @kernel_function(
        name="get_drive",
        description="Gets the user's OneDrive file store."
    )
    async def get_drive(
        self,
        user_id: Annotated[str, "The ID or userPrincipalName of the user."]
    ) -> str:
        """Gets the user's OneDrive file store."""
        drive = await self._client.users.by_user_id(user_id).drive.get()
        if drive:
            return json.dumps(drive.__dict__)
        return json.dumps({"error": "Drive not found"})

    @kernel_function(
        name="list_member_of",
        description="Lists the groups that the user is a member of."
    )
    async def list_member_of(
        self,
        user_id: Annotated[str, "The ID or userPrincipalName of the user."],
        top: Annotated[int, "Number of items to return per page."] = None,
        skiptoken: Annotated[str, "The skip token for pagination."] = None
    ) -> str:
        """Lists the groups that the user is a member of."""
        request_config = MemberOfRequestBuilder.MemberOfRequestBuilderGetRequestConfiguration()
        if top:
            request_config.query_parameters.top = top
        if skiptoken:
            request_config.query_parameters.skiptoken = skiptoken
        groups_page = await self._client.users.by_user_id(user_id).member_of.get(request_configuration=request_config)
        result = {
            "value": [group.__dict__ for group in groups_page.value] if groups_page and groups_page.value else [],
            "next_link": groups_page.odata_next_link if groups_page else None
        }
        return json.dumps(result)

    @kernel_function(
        name="list_joined_teams",
        description="Lists the Microsoft Teams that the user is a member of."
    )
    async def list_joined_teams(
        self,
        user_id: Annotated[str, "The ID or userPrincipalName of the user."],
        top: Annotated[int, "Number of items to return per page."] = None,
        skiptoken: Annotated[str, "The skip token for pagination."] = None
    ) -> str:
        """Lists the Microsoft Teams that the user is a member of."""
        request_config = JoinedTeamsRequestBuilder.JoinedTeamsRequestBuilderGetRequestConfiguration()
        if top:
            request_config.query_parameters.top = top
        if skiptoken:
            request_config.query_parameters.skiptoken = skiptoken
        teams_page = await self._client.users.by_user_id(user_id).joined_teams.get(request_configuration=request_config)
        result = {
            "value": [team.__dict__ for team in teams_page.value] if teams_page and teams_page.value else [],
            "next_link": teams_page.odata_next_link if teams_page else None
        }
        return json.dumps(result)

    @kernel_function(
        name="create_invitation",
        description="Invites a guest user as part of B2B collaboration."
    )
    async def create_invitation(
        self,
        invited_user_email: Annotated[str, "The email address of the invited user."],
        redirect_url: Annotated[str, "The URL to redirect after invitation redemption."]
    ) -> str:
        """Invites a guest user as part of B2B collaboration."""
        invitation = Invitation()
        invitation.invited_user_email_address = invited_user_email
        invitation.invite_redirect_url = redirect_url
        result = await self._client.invitations.post(invitation)
        if result:
            return json.dumps(result.__dict__)
        return json.dumps({"error": "Invitation failed"})

    @kernel_function(
        name="update_user",
        description="Updates a user's profile. Provide updates as a JSON string of properties."
    )
    async def update_user(
        self,
        user_id: Annotated[str, "The ID or userPrincipalName of the user."],
        updates: Annotated[str, "JSON string of properties to update (e.g., {'displayName': 'New Name'})."]
    ) -> str:
        """Updates a user's profile."""
        update_dict = json.loads(updates)
        user = User(**update_dict)
        await self._client.users.by_user_id(user_id).patch(user)
        return json.dumps({"success": True})

    @kernel_function(
        name="change_password",
        description="Changes the password for the signed-in user."
    )
    async def change_password(
        self,
        current_password: Annotated[str, "The current password."],
        new_password: Annotated[str, "The new password."]
    ) -> str:
        """Changes the password for the signed-in user."""
        request_body = ChangePasswordRequestBody()
        request_body.current_password = current_password
        request_body.new_password = new_password
        await self._client.me.change_password.post(request_body)
        return json.dumps({"success": True})