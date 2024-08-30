import json
from channels.generic.websocket import (
    AsyncWebsocketConsumer,
)  # for creating asynchronous WebSocket consumers.


class AlertConsumer(AsyncWebsocketConsumer):
    """
    A WebSocket consumer for handling real-time alert notifications.

    This consumer subscribes to the "alerts" group and broadcasts incoming alert messages
    to connected clients.
    """

    async def connect(self):
        """
        Handles the connection of a WebSocket client.

        Adds the client to the "alerts" group to receive alert messages.
        """
        await self.channel_layer.group_add("alerts", self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        """
        Handles the disconnection of a WebSocket client.

        Removes the client from the "alerts" group.
        """
        await self.channel_layer.group_discard("alerts", self.channel_name)

    async def receive(self, text_data):
        """
        Handles incoming WebSocket messages.

        Parses the received JSON data and sends a message to the "alerts" group,
        broadcasting the alert to all connected clients.
        """
        data = json.loads(text_data)
        await self.channel_layer.group_send(
            "alerts",
            {
                "type": "send_alert",
                "message": data["message"],
                "id": data["id"],
                "severity": data["severity"],
                "rule_name": data["rule_name"],
            },
        )

    async def send_alert(self, event):
        """
        Handles incoming alert messages from the "alerts" group.

        Sends the alert message to the connected client as a WebSocket message.
        """
        message = event["message"]
        severity = event["severity"]
        rule_name = event["rule_name"]
        id = event["id"]

        await self.send(
            text_data=json.dumps(
                {
                    "message": message,
                    "severity": severity,
                    "rule_name": rule_name,
                    "id": id,
                }
            )
        )
