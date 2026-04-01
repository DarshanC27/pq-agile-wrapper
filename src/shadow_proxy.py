"""
Shadow Proxy — Main TCP Proxy Server
=====================================

The core "Security Sidecar" that:
  1. Listens for incoming TCP connections
  2. Evaluates each connection's metadata against NCSC criteria
  3. If shield required: applies ML-KEM Shadow Wrap via the Crypto Engine
  4. Forwards the (possibly wrapped) data to the upstream legacy server
  5. Returns responses back to the client

This is the entry point for the entire system.

Usage:
    python -m src.shadow_proxy --config config/default.yaml
"""

import asyncio
import argparse
import time
import signal
import sys
from typing import Optional

from .config import load_config, AppConfig
from .logger import setup_logger, get_logger
from .crypto_engine import CryptoEngine, ShadowWrappedPacket
from .metadata_evaluator import MetadataEvaluator, Action
from .key_vault import KeyVault
from .failsafe import FailsafeMonitor, FailsafeState


class ShadowProxy:
    """
    The Shadow Proxy server.

    Sits between clients and legacy servers, transparently adding
    a post-quantum encryption layer to sensitive data streams.
    """

    def __init__(self, config: AppConfig):
        self.config = config
        self.log = get_logger()

        # Initialise components
        self.crypto = CryptoEngine(algorithm=config.crypto.kem_algorithm)
        self.evaluator = MetadataEvaluator(config.classifier)
        self.vault = KeyVault(config.crypto, config.vault)
        self.failsafe = FailsafeMonitor(config.failsafe)

        # Stats
        self._connections_handled = 0
        self._bytes_processed = 0
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False

    async def start(self):
        """Start the Shadow Proxy server."""
        self.log.info("=" * 60)
        self.log.info("  PQ Agile Wrapper — Shadow Proxy")
        self.log.info(f"  Algorithm: {self.config.crypto.kem_algorithm}")
        self.log.info(f"  Backend: {self.crypto.backend}")
        self.log.info(f"  Listen: {self.config.proxy.listen_host}:{self.config.proxy.listen_port}")
        self.log.info(f"  Forward: {self.config.proxy.forward_host}:{self.config.proxy.forward_port}")
        self.log.info("=" * 60)

        # Pre-generate an initial keypair
        self.vault.get_active_keypair()

        # Start the TCP server
        self._server = await asyncio.start_server(
            self._handle_connection,
            self.config.proxy.listen_host,
            self.config.proxy.listen_port,
        )
        self._running = True

        addr = self._server.sockets[0].getsockname()
        self.log.info(f"Shadow Proxy listening on {addr[0]}:{addr[1]}")

        async with self._server:
            await self._server.serve_forever()

    async def stop(self):
        """Gracefully stop the proxy."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        self.vault.save_to_disk()
        self.log.info("Shadow Proxy stopped.")
        self._print_stats()

    async def _handle_connection(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ):
        """Handle a single client connection."""
        peer = client_writer.get_extra_info("peername")
        self._connections_handled += 1
        conn_id = self._connections_handled

        self.log.info(f"[CONN-{conn_id}] New connection from {peer}")

        try:
            # Read the incoming data from the client
            data = await asyncio.wait_for(
                client_reader.read(self.config.proxy.buffer_size),
                timeout=30.0,
            )

            if not data:
                self.log.debug(f"[CONN-{conn_id}] Empty request, closing.")
                client_writer.close()
                return

            self._bytes_processed += len(data)

            # --- Step 1: Extract metadata and evaluate ---
            data_class = self._extract_metadata(data)
            result = self.evaluator.evaluate(metadata_header=data_class)

            # --- Step 2: Apply Shadow Wrap if needed ---
            if result.action == Action.APPLY_SHIELD and self.failsafe.is_pq_active:
                forward_data = await self._apply_shadow_wrap(data, conn_id)
            else:
                if not self.failsafe.is_pq_active:
                    self.log.warning(
                        f"[CONN-{conn_id}] Failsafe active — forwarding with "
                        f"classical encryption only."
                    )
                forward_data = data

            # --- Step 3: Forward to upstream legacy server ---
            response = await self._forward_to_upstream(forward_data, conn_id)

            # --- Step 4: Send response back to client ---
            if response:
                client_writer.write(response)
                await client_writer.drain()

        except asyncio.TimeoutError:
            self.log.warning(f"[CONN-{conn_id}] Connection timed out.")
        except ConnectionRefusedError:
            self.log.error(
                f"[CONN-{conn_id}] Upstream server refused connection at "
                f"{self.config.proxy.forward_host}:{self.config.proxy.forward_port}"
            )
            # Send error response to client
            error_msg = b"HTTP/1.1 502 Bad Gateway\r\n\r\nUpstream unavailable"
            client_writer.write(error_msg)
            await client_writer.drain()
        except Exception as e:
            self.log.error(f"[CONN-{conn_id}] Error: {e}")
        finally:
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except Exception:
                pass

    def _extract_metadata(self, data: bytes) -> Optional[str]:
        """
        Extract the data classification metadata from the packet.

        Looks for the X-PQ-Data-Class header in HTTP-like traffic.
        For non-HTTP traffic, falls back to the default action.
        """
        try:
            # Try to parse as HTTP headers
            header_end = data.find(b"\r\n\r\n")
            if header_end == -1:
                return None

            headers_raw = data[:header_end].decode("utf-8", errors="ignore")
            header_name = self.config.classifier.metadata_header.lower()

            for line in headers_raw.split("\r\n"):
                if ":" in line:
                    key, value = line.split(":", 1)
                    if key.strip().lower() == header_name.lower():
                        return value.strip()

        except Exception:
            pass

        return None

    async def _apply_shadow_wrap(self, data: bytes, conn_id: int) -> bytes:
        """
        Apply the ML-KEM Shadow Wrap to the data.

        Returns the wrapped data bytes, or original data if wrapping fails.
        """
        start = time.perf_counter()

        try:
            # Get the active keypair from the vault
            keypair = self.vault.get_active_keypair()
            if keypair is None:
                self.failsafe.check_vault_health(is_reachable=False)
                self.log.error(f"[CONN-{conn_id}] Vault returned no keypair!")
                return data

            # Apply the Shadow Wrap
            wrapped = self.crypto.shadow_wrap(data, keypair.public_key)
            wrapped_bytes = wrapped.to_bytes()

            elapsed_ms = (time.perf_counter() - start) * 1000
            self.failsafe.check_latency(elapsed_ms)

            overhead = len(wrapped_bytes) - len(data)
            self.log.info(
                f"[CONN-{conn_id}] Shadow Wrap applied: "
                f"{len(data)}B → {len(wrapped_bytes)}B "
                f"(+{overhead}B overhead, {elapsed_ms:.2f}ms)"
            )

            return wrapped_bytes

        except Exception as e:
            self.log.error(
                f"[CONN-{conn_id}] Shadow Wrap FAILED: {e} — "
                f"forwarding with classical encryption only."
            )
            return data

    async def _forward_to_upstream(
        self, data: bytes, conn_id: int
    ) -> Optional[bytes]:
        """Forward data to the upstream legacy server and return the response."""
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.config.proxy.forward_host,
                    self.config.proxy.forward_port,
                ),
                timeout=10.0,
            )

            upstream_writer.write(data)
            await upstream_writer.drain()

            response = await asyncio.wait_for(
                upstream_reader.read(self.config.proxy.buffer_size),
                timeout=30.0,
            )

            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except Exception:
                pass

            self.log.debug(
                f"[CONN-{conn_id}] Upstream responded with {len(response)}B"
            )
            return response

        except Exception as e:
            self.log.error(f"[CONN-{conn_id}] Upstream error: {e}")
            raise

    def _print_stats(self):
        """Print final statistics."""
        self.log.info("--- Shadow Proxy Statistics ---")
        self.log.info(f"  Connections handled: {self._connections_handled}")
        self.log.info(f"  Bytes processed: {self._bytes_processed}")
        self.log.info(f"  Crypto stats: {self.crypto.stats}")
        self.log.info(f"  Evaluator stats: {self.evaluator.stats}")
        self.log.info(f"  Vault stats: {self.vault.stats}")
        self.log.info(f"  Failsafe stats: {self.failsafe.stats}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="PQ Agile Wrapper — Shadow Proxy")
    parser.add_argument(
        "--config", "-c",
        default=None,
        help="Path to YAML configuration file",
    )
    args = parser.parse_args()

    # Load configuration
    config = load_config(args.config)

    # Setup logging
    setup_logger(
        level=config.logging.level,
        fmt=config.logging.format,
        log_file=config.logging.log_file,
    )

    # Create and run the proxy
    proxy = ShadowProxy(config)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def shutdown_handler(sig, frame):
        print("\nShutting down...")
        loop.create_task(proxy.stop())
        loop.stop()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        loop.run_until_complete(proxy.start())
    except KeyboardInterrupt:
        loop.run_until_complete(proxy.stop())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
