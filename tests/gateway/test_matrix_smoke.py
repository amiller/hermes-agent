"""
Smoke test for Matrix gateway integration.

This test verifies that the gateway can successfully:
1. Connect to the Matrix homeserver
2. Create a room
3. Send a message

This is a basic integration test that serves as a precondition for
more advanced HERMES-GW-N tests.
"""

import pytest
from mautrix.types import RoomID


@pytest.mark.asyncio
async def test_gateway_can_create_room_and_send_message(
    gateway_client,
    test_room: RoomID
):
    """
    Test that the gateway client can create a room and send a message.

    This test verifies the basic Matrix client functionality:
    - Room creation (via test_room fixture)
    - Message sending
    """
    # Send a test message
    test_message = "hello"
    await gateway_client.send_notice(
        room_id=test_room,
        text=test_message
    )

    # If we got here without exceptions, the message was sent successfully
    assert True, "Message sent successfully"
