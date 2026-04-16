"""
Smoke test for Matrix gateway integration.

This test verifies that the gateway can successfully:
1. Connect to the Matrix homeserver
2. Create a room
3. Send a message
4. Read the message back and verify its content

This is a basic integration test that serves as a precondition for
more advanced HERMES-GW-N tests.
"""

import pytest
import asyncio
from mautrix.types import RoomID, EventID, EventType, PaginationDirection
from mautrix.client import Client
from typing import Tuple


@pytest.mark.asyncio
async def test_gateway_can_create_room_and_send_message(
    gateway_client: Client,
    test_room: RoomID
) -> None:
    """
    Test that the gateway client can create a room, send a message, and read it back.

    This test verifies the basic Matrix client functionality:
    - Room creation (via test_room fixture)
    - Message sending with event ID verification
    - Message reading and content verification
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

    # Wait a moment for the event to be available in the room history
    await asyncio.sleep(0.5)

    # Read back the message from the room history
    messages_resp = await gateway_client.get_messages(
        room_id=test_room,
        direction=PaginationDirection.BACKWARD,
        limit=10
    )

    # Find our test message in the results
    found_message = None
    for event in messages_resp.events:
        if event.event_id == event_id:
            # Check if this is a message event with body content
            if hasattr(event, 'content'):
                content = event.content
                if hasattr(content, 'body'):
                    found_message = content.body
                    break

    # Verify we found the message and it matches what we sent
    assert found_message is not None, f"Message with event ID {event_id} not found in room history"
    assert found_message == test_message, f"Message content mismatch: expected '{test_message}', got '{found_message}'"
