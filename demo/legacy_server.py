"""
Demo Legacy Server
==================

A simple HTTP server that simulates a legacy application
(e.g., a Surrey council database or satellite ground station).

This is the "upstream" server that the Shadow Proxy forwards to.
"""

import asyncio
import json
from datetime import datetime


MOCK_RESPONSES = {
    "pension": {
        "type": "pension_record",
        "employee_id": "SCC-2024-8812",
        "name": "J. Smith",
        "pension_fund": "Surrey County Council LGPS",
        "annual_amount": "£18,450",
        "retirement_date": "2052-06-01",
        "status": "active",
    },
    "satellite": {
        "type": "satellite_key",
        "satellite_id": "SSTL-SURREY-07",
        "key_purpose": "TT&C Uplink Encryption",
        "algorithm": "AES-256",
        "key_hash": "a3f8c1...b72e",
        "valid_until": "2055-12-31",
        "classification": "CONFIDENTIAL",
    },
    "default": {
        "type": "general_response",
        "server": "Surrey Legacy App v2.1",
        "message": "Request processed successfully",
        "timestamp": None,
    },
}


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Handle incoming requests from the Shadow Proxy."""
    peer = writer.get_extra_info("peername")
    data = await reader.read(65536)

    if not data:
        writer.close()
        return

    # Parse the request to determine response type
    request_text = data.decode("utf-8", errors="ignore")
    response_data = MOCK_RESPONSES["default"].copy()
    response_data["timestamp"] = datetime.now().isoformat()

    if "pension" in request_text.lower() or "pension_records" in request_text.lower():
        response_data = MOCK_RESPONSES["pension"]
    elif "satellite" in request_text.lower() or "satellite_keys" in request_text.lower():
        response_data = MOCK_RESPONSES["satellite"]

    body = json.dumps(response_data, indent=2)
    http_response = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Server: Surrey-Legacy/2.1\r\n"
        f"\r\n"
        f"{body}"
    )

    writer.write(http_response.encode())
    await writer.drain()
    writer.close()
    print(f"  [Legacy Server] Responded to {peer} with {response_data.get('type', 'unknown')}")


async def main():
    server = await asyncio.start_server(handle_client, "127.0.0.1", 8080)
    addr = server.sockets[0].getsockname()
    print(f"[Legacy Server] Running on {addr[0]}:{addr[1]}")
    print(f"[Legacy Server] Simulating Surrey council / satellite database")
    print()

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
