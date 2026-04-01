"""
Demo Client
============

Sends test requests through the Shadow Proxy to demonstrate:
  1. Data classification (which streams get the Shield)
  2. Transparent proxying (client doesn't need to change)
  3. Different data types getting different treatment
"""

import asyncio
import sys


async def send_request(
    host: str,
    port: int,
    data_class: str,
    path: str = "/api/data",
    body: str = "",
):
    """Send a single HTTP request through the Shadow Proxy."""
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: legacy-server.surrey.local\r\n"
        f"X-PQ-Data-Class: {data_class}\r\n"
        f"User-Agent: SurreyClient/1.0\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )

    try:
        reader, writer = await asyncio.open_connection(host, port)
        writer.write(request.encode())
        await writer.drain()

        response = await asyncio.wait_for(reader.read(65536), timeout=10.0)
        writer.close()
        await writer.wait_closed()

        return response.decode("utf-8", errors="ignore")

    except ConnectionRefusedError:
        return f"ERROR: Could not connect to {host}:{port}"
    except asyncio.TimeoutError:
        return "ERROR: Request timed out"


async def main():
    proxy_host = "127.0.0.1"
    proxy_port = 8443

    print("=" * 65)
    print("  PQ Agile Wrapper — Demo Client")
    print(f"  Sending requests through Shadow Proxy at {proxy_host}:{proxy_port}")
    print("=" * 65)
    print()

    # Test cases: different data classifications
    test_cases = [
        {
            "name": "Satellite Encryption Keys",
            "data_class": "satellite_keys",
            "description": "30-year shelf life → MUST be shielded (expires 2056)",
        },
        {
            "name": "Pension Records",
            "data_class": "pension_records",
            "description": "50-year shelf life → MUST be shielded (expires 2076)",
        },
        {
            "name": "Research IP",
            "data_class": "research_ip",
            "description": "25-year shelf life → MUST be shielded (expires 2051)",
        },
        {
            "name": "General Communications",
            "data_class": "general_comms",
            "description": "5-year shelf life → PASS THROUGH (expires 2031)",
        },
        {
            "name": "Unclassified Data",
            "data_class": "",
            "description": "No metadata → default action (shield by policy)",
        },
    ]

    for i, tc in enumerate(test_cases, 1):
        print(f"--- Test {i}: {tc['name']} ---")
        print(f"    Class: {tc['data_class'] or '(none)'}")
        print(f"    Expected: {tc['description']}")
        print()

        response = await send_request(
            proxy_host,
            proxy_port,
            data_class=tc["data_class"],
            path=f"/api/{tc['data_class'] or 'unknown'}",
        )

        # Show first 200 chars of response
        preview = response[:200] + ("..." if len(response) > 200 else "")
        print(f"    Response: {preview}")
        print()

    print("=" * 65)
    print("  All test cases completed.")
    print("  Check the Shadow Proxy logs for classification decisions.")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(main())
