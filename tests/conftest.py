"""
Pytest fixtures for Matrix gateway integration tests.

These fixtures provide a common setup for all HERMES-GW-N tests:
- hs_url: The Matrix homeserver URL
- gateway_client: A logged-in mautrix AsyncClient as the gateway user
- test_room: A test room for sending/receiving messages
"""

import os
import pytest
import pytest_asyncio
import asyncio
import logging
from mautrix.client import Client
from mautrix.types import UserID, RoomCreatePreset

logger = logging.getLogger(__name__)


@pytest.fixture(scope="session")
def hs_url() -> str:
    """
    Return the Matrix homeserver URL.

    Inside the docker-compose network, the homeserver is accessible
    as 'conduit:6167'.
    """
    return os.environ.get("HERMES_HS_URL", "http://conduit:6167")


@pytest_asyncio.fixture
async def gateway_client(hs_url: str) -> Client:
    """
    Create and authenticate the gateway user, returning a logged-in Client.

    This fixture provides a mautrix AsyncClient that is already
    authenticated and ready to use for Matrix operations.
    """
    gateway_user_str = os.environ.get("HERMES_MATRIX_USER", "@gateway:conduit")
    gateway_localpart = gateway_user_str.split(":")[0][1:]  # Extract "gateway" from "@gateway:conduit"
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
        logger.info(f"Gateway user '{gateway_localpart}' registered successfully")
    except Exception as e:
        # User might already exist, try login instead
        if "already in use" in str(e) or "User already exists" in str(e):
            logger.info(f"Gateway user '{gateway_localpart}' already exists, proceeding to login")
        elif "network" in str(e).lower() or "timeout" in str(e).lower() or "connection" in str(e).lower():
            logger.error(f"Network/timeout error during gateway registration: {e}")
            raise
        else:
            logger.warning(f"Registration attempt failed (user may exist): {e}")

    # Login
    resp = await client.login(
        password=gateway_password,
        device_name="pytest-gateway"
    )
    logger.info(f"Gateway user '{gateway_localpart}' logged in successfully")

    yield client

    # Cleanup: logout and disconnect to avoid resource leaks
    try:
        await client.logout()
        logger.info(f"Gateway user '{gateway_localpart}' logged out successfully")
    except Exception as e:
        logger.error(f"Error during gateway logout: {e}")
    finally:
        # Always disconnect to avoid resource leaks
        try:
            await client.disconnect()
            logger.info("Gateway client disconnected successfully")
        except Exception as e:
            logger.error(f"Error disconnecting gateway client: {e}")


@pytest_asyncio.fixture
async def test_room(gateway_client: Client) -> str:
    """
    Create a test room and return its room ID.

    This fixture creates a new room for each test that needs it,
    and cleans it up after the test completes.
    """
    try:
        room_id = await gateway_client.create_room(
            name="Test Room",
            preset=RoomCreatePreset.PUBLIC
        )
        logger.info(f"Test room created: {room_id}")
        yield room_id
    except Exception as e:
        if "network" in str(e).lower() or "timeout" in str(e).lower() or "connection" in str(e).lower():
            logger.error(f"Network/timeout error creating test room: {e}")
        raise
    finally:
        # Cleanup: leave the room
        try:
            await gateway_client.leave_room(room_id)
            logger.info(f"Left test room: {room_id}")
        except Exception as e:
            logger.error(f"Error leaving test room: {e}")
