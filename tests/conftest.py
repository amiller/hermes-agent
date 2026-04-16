"""
Pytest fixtures for Matrix gateway integration tests.

These fixtures provide a common setup for all HERMES-GW-N tests:
- hs_url: The Matrix homeserver URL
- admin_token: An authenticated admin user token
- gateway_client: A logged-in mautrix AsyncClient as the gateway user
- test_room: A test room for sending/receiving messages
"""

import os
import pytest
import pytest_asyncio
import asyncio
from mautrix.client import Client
from mautrix.types import UserID, RoomCreatePreset


@pytest.fixture(scope="session")
def hs_url() -> str:
    """
    Return the Matrix homeserver URL.

    Inside the docker-compose network, the homeserver is accessible
    as 'conduwuit:6167'.
    """
    return os.environ.get("HERMES_HS_URL", "http://conduwuit:6167")


@pytest.fixture(scope="session")
def admin_token(hs_url: str) -> str:
    """
    Create and authenticate an admin user, returning the access token.

    This fixture runs once per test session to create an admin user
    for the test suite. The admin credentials are from environment
    variables or defaults.
    """
    admin_user = UserID("@admin:conduwuit")
    admin_password = os.environ.get("HERMES_ADMIN_PASSWORD", "admin_password")

    # Create client and login
    client = Client(
        base_url=hs_url,
    )
    client._mxid = admin_user

    # Register the admin user (if not already exists)
    try:
        asyncio.run(client.register(
            username="admin",
            password=admin_password,
            device_name="pytest-admin"
        ))
    except Exception as e:
        # User might already exist, try login instead
        pass

    # Login to get access token
    resp = asyncio.run(client.login(
        password=admin_password,
        device_name="pytest-admin"
    ))

    return resp.access_token


@pytest_asyncio.fixture
async def gateway_client(hs_url: str) -> Client:
    """
    Create and authenticate the gateway user, returning a logged-in Client.

    This fixture provides a mautrix AsyncClient that is already
    authenticated and ready to use for Matrix operations.
    """
    gateway_user_str = os.environ.get("HERMES_MATRIX_USER", "@gateway:conduwuit")
    gateway_localpart = gateway_user_str.split(":")[0][1:]  # Extract "gateway" from "@gateway:conduwuit"
    gateway_password = os.environ.get("HERMES_MATRIX_PASSWORD", "gateway_password")

    client = Client(
        base_url=hs_url,
    )
    client._mxid = UserID(gateway_user_str)

    # Register the gateway user (if not already exists)
    try:
        # Use direct API call for registration with required auth
        resp = await client.api.request(
            method="POST",
            path="/_matrix/client/v3/register",
            content={
                "username": gateway_localpart,
                "password": gateway_password,
                "auth": {"type": "m.login.dummy"}
            }
        )
    except Exception as e:
        # User might already exist, try login instead
        pass

    # Login
    resp = await client.login(
        password=gateway_password,
        device_name="pytest-gateway"
    )

    yield client

    # Cleanup: logout
    try:
        await client.logout()
    except Exception:
        pass


@pytest_asyncio.fixture
async def test_room(gateway_client: Client) -> str:
    """
    Create a test room and return its room ID.

    This fixture creates a new room for each test that needs it,
    and cleans it up after the test completes.
    """
    room_id = await gateway_client.create_room(
        name="Test Room",
        preset=RoomCreatePreset.PUBLIC
    )

    yield room_id

    # Cleanup: leave and close the room
    try:
        await gateway_client.leave_room(room_id)
    except Exception:
        pass
