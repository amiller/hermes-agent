"""
Pytest fixtures for Matrix gateway testing.

These fixtures provide the necessary Matrix client setup for testing
the Hermes Matrix gateway integration with a local homeserver.
"""

import os
import asyncio
from typing import AsyncGenerator
import pytest

from mautrix.client import Client
from mautrix.types import UserID, RoomID


@pytest.fixture(scope="session")
def hs_url() -> str:
    """Get the homeserver URL from environment or use default."""
    return os.getenv("HERMES_HS_URL", "http://conduwuit:6167")


@pytest.fixture(scope="session")
def admin_username() -> str:
    """Get the admin username from environment or use default."""
    return os.getenv("HERMES_ADMIN_USERNAME", "admin")


@pytest.fixture(scope="session")
def admin_password() -> str:
    """Get the admin password from environment or use default."""
    return os.getenv("HERMES_ADMIN_PASSWORD", "admin_password")


@pytest.fixture(scope="session")
def gateway_username() -> str:
    """Get the gateway username from environment or use default."""
    user = os.getenv("HERMES_MATRIX_USER", "@gateway:conduwuit")
    # Extract localpart if full mxid is provided
    if user.startswith("@"):
        return user.split(":")[0][1:]
    return user


@pytest.fixture(scope="session")
def gateway_password() -> str:
    """Get the gateway password from environment or use default."""
    return os.getenv("HERMES_MATRIX_PASSWORD", "gateway_password")


@pytest.fixture(scope="session")
async def admin_client(
    hs_url: str,
    admin_username: str,
    admin_password: str
) -> AsyncGenerator[Client, None]:
    """
    Create and authenticate an admin client.
    
    This fixture provides a client with admin privileges for setting up
    the test environment (e.g., creating users, rooms, etc.).
    """
    client = Client(
        base_url=hs_url,
        user_id=UserID(f"@{admin_username}:conduwuit"),
    )
    
    # Log in
    await client.login(
        username=admin_username,
        password=admin_password,
        device_name="hermes-test-admin"
    )
    
    yield client
    
    # Cleanup
    try:
        await client.logout()
    except Exception:
        pass
    await client.disconnect()


@pytest.fixture(scope="session")
async def gateway_client(
    hs_url: str,
    gateway_username: str,
    gateway_password: str,
    admin_client: Client
) -> AsyncGenerator[Client, None]:
    """
    Create and authenticate the gateway client.
    
    This fixture provides a client representing the Hermes gateway user.
    It ensures the user is registered and logged in.
    """
    client = Client(
        base_url=hs_url,
        user_id=UserID(f"@{gateway_username}:conduwuit"),
    )
    
    # Try to log in, if that fails, try to register first
    try:
        await client.login(
            username=gateway_username,
            password=gateway_password,
            device_name="hermes-gateway"
        )
    except Exception as login_error:
        # Registration might be needed
        try:
            # For conduwuit, we can register via the client API
            await client.register(
                username=gateway_username,
                password=gateway_password,
                device_name="hermes-gateway"
            )
        except Exception as register_error:
            pytest.skip(f"Failed to both login and register gateway user: {register_error}")
    
    yield client
    
    # Cleanup
    try:
        await client.logout()
    except Exception:
        pass
    await client.disconnect()


@pytest.fixture(scope="function")
async def test_room(
    gateway_client: Client
) -> AsyncGenerator[RoomID, None]:
    """
    Create a test room and clean it up after the test.
    
    This fixture creates a new room for each test function and ensures
    it's properly cleaned up afterward.
    """
    # Create a new room
    response = await gateway_client.create_room(
        name="Test Room",
        preset="private_chat"
    )
    room_id = RoomID(response["room_id"])
    
    yield room_id
    
    # Cleanup: leave and potentially delete the room
    try:
        await gateway_client.leave_room(room_id)
    except Exception:
        pass
