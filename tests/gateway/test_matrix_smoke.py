"""
Smoke test for Matrix gateway integration.

This test verifies that the gateway can successfully:
1. Connect to the Matrix homeserver
2. Create a room
3. Send a message
4. Verify the message was sent

This is a basic integration test that serves as a precondition for
more advanced HERMES-GW-N tests.
"""

import pytest
from mautrix.types import RoomID, EventID
from mautrix.client import Client
from typing import Tuple


@pytest.mark.asyncio
async def test_gateway_can_create_room_and_send_message(
    gateway_client: Client,
    test_room: RoomID
) -> Tuple[RoomID, EventID]:
    """
    Test that the gateway client can create a room and send a message.

    This test verifies the basic Matrix client functionality:
    - Room creation (via test_room fixture)
    - Message sending with event ID verification
    """
    # Send a test message and capture the event ID
    test_message = "hello"
    event_id = await gateway_client.send_notice(
        room_id=test_room,
        text=test_message
    )

    # Verify the event ID is valid
    assert event_id is not None, "Event ID should not be None after sending message"
    assert isinstance(event_id, str), "Event ID should be a string"
    assert "$" in event_id, "Event ID should start with $ (Matrix event format)"

    # Return room_id and event_id for potential use in derived tests
    return test_room, event_id
