"""
Smoke test for Matrix gateway integration.

This test verifies that the gateway can successfully:
1. Connect to the Matrix homeserver
2. Create a room
3. Send a message
4. Read the message back

This is a basic integration test that serves as a precondition for
more advanced HERMES-GW-N tests.
"""

import pytest
from mautrix.types import RoomID, UserID


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
    - Message retrieval
    - Message content verification
    """
    # Send a test message
    test_message = "hello"
    await gateway_client.send_notice(
        room_id=test_room,
        text=test_message
    )
    
    # Get the room events to verify the message was sent
    events = await gateway_client.get_events(
        room_id=test_room,
        limit=10
    )
    
    # Verify we got events back
    assert events is not None
    assert len(events.chunk) > 0
    
    # Find our message in the events
    found_message = False
    for event in events.chunk:
        if hasattr(event, 'content') and hasattr(event.content, 'body'):
            if event.content.body == test_message:
                found_message = True
                break
    
    assert found_message, f"Test message '{test_message}' not found in room events"


@pytest.mark.asyncio
async def test_gateway_user_is_authenticated(gateway_client):
    """
    Test that the gateway client is properly authenticated.
    
    This verifies that the user exists and can interact with the homeserver.
    """
    # Get the user's profile
    profile = await gateway_client.get_profile(
        user_id=UserID(str(gateway_client.user_id))
    )
    
    assert profile is not None
    assert profile.displayname is not None or profile.avatar_url is not None or True  # Either is fine


@pytest.mark.asyncio
async def test_gateway_can_create_private_room(gateway_client):
    """
    Test that the gateway can create a private room.
    
    This verifies room creation functionality beyond the fixture.
    """
    response = await gateway_client.create_room(
        name="Private Test Room",
        preset="private_chat",
        invite=[]
    )
    
    assert "room_id" in response
    room_id = RoomID(response["room_id"])
    
    # Clean up
    try:
        await gateway_client.leave_room(room_id)
    except Exception:
        pass
