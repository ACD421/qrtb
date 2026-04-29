"""
QRTB P2P Networking Layer
- asyncio-based TCP server and client
- Length-prefixed message framing
- Peer discovery and heartbeat
- Broadcast and targeted messaging
"""

import asyncio
import struct
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Tuple, Set
from enum import IntEnum

from .crypto import sha3_256, secure_random

# =============================================================================
# CONSTANTS
# =============================================================================

HEARTBEAT_INTERVAL = 30      # seconds between PINGs
HEARTBEAT_TIMEOUT = 90       # seconds before disconnect
MAX_PEERS = 50               # maximum connected peers per node
MAX_MESSAGE_SIZE = 16 * 1024 * 1024  # 16 MB max message
HEADER_SIZE = 5              # 4-byte length + 1-byte msg_type

logger = logging.getLogger("qrtb.p2p")


# =============================================================================
# MESSAGE TYPES
# =============================================================================

class MessageType(IntEnum):
    PING = 0
    PONG = 1
    PEER_DISCOVERY = 2
    PEER_LIST = 3
    TX_BROADCAST = 4
    MEASUREMENT_COMMIT = 5
    MEASUREMENT_REVEAL = 6
    PROPOSAL = 7
    PRE_VOTE = 8
    PRE_COMMIT = 9
    BLOCK = 10
    EPOCH_SYNC = 11


# =============================================================================
# PEER INFO
# =============================================================================

@dataclass
class PeerConnection:
    """Tracks a connected peer"""
    validator_id: bytes
    address: str            # "host:port"
    zone_id: int
    stake: int
    last_seen: float = 0.0
    reader: Optional[asyncio.StreamReader] = field(default=None, repr=False)
    writer: Optional[asyncio.StreamWriter] = field(default=None, repr=False)
    outbound: bool = False  # True if we initiated the connection


# =============================================================================
# MESSAGE FRAMING
# =============================================================================

def encode_message(msg_type: MessageType, payload: bytes) -> bytes:
    """
    Encode a message with framing header.

    Wire format: [4-byte payload length BE][1-byte msg_type][payload]
    """
    header = struct.pack(">IB", len(payload), int(msg_type))
    return header + payload


async def read_message(reader: asyncio.StreamReader) -> Tuple[MessageType, bytes]:
    """
    Read one framed message from the stream.

    Returns (msg_type, payload).
    Raises ConnectionError on EOF or protocol violation.
    """
    header = await reader.readexactly(HEADER_SIZE)
    payload_len, msg_type_int = struct.unpack(">IB", header)

    if payload_len > MAX_MESSAGE_SIZE:
        raise ConnectionError(f"Message too large: {payload_len}")

    if msg_type_int > max(MessageType):
        raise ConnectionError(f"Unknown message type: {msg_type_int}")

    payload = await reader.readexactly(payload_len) if payload_len > 0 else b""
    return MessageType(msg_type_int), payload


# =============================================================================
# PEER MANAGER
# =============================================================================

class PeerManager:
    """
    Manages connected peers, discovery, and heartbeat.
    """

    def __init__(self, validator_id: bytes, zone_id: int, stake: int):
        self.validator_id = validator_id
        self.zone_id = zone_id
        self.stake = stake

        # Connected peers keyed by validator_id
        self.peers: Dict[bytes, PeerConnection] = {}

        # Seed nodes for bootstrapping: list of (host, port)
        self.seed_nodes: List[Tuple[str, int]] = []

        # Known addresses we have seen but may not be connected to
        self.known_addresses: Set[str] = set()

    @property
    def peer_count(self) -> int:
        return len(self.peers)

    def can_accept_peer(self) -> bool:
        return self.peer_count < MAX_PEERS

    def add_seed_nodes(self, seeds: List[Tuple[str, int]]) -> None:
        """Register seed nodes for bootstrapping."""
        for host, port in seeds:
            self.seed_nodes.append((host, port))
            self.known_addresses.add(f"{host}:{port}")

    def add_peer(self, peer: PeerConnection) -> bool:
        """Add a connected peer. Returns False if at capacity."""
        if not self.can_accept_peer():
            return False
        if peer.validator_id == self.validator_id:
            return False
        self.peers[peer.validator_id] = peer
        self.known_addresses.add(peer.address)
        return True

    def remove_peer(self, validator_id: bytes) -> Optional[PeerConnection]:
        """Remove and return a peer."""
        return self.peers.pop(validator_id, None)

    def get_peer(self, validator_id: bytes) -> Optional[PeerConnection]:
        return self.peers.get(validator_id)

    def touch_peer(self, validator_id: bytes) -> None:
        """Update last_seen for a peer."""
        peer = self.peers.get(validator_id)
        if peer:
            peer.last_seen = time.time()

    def get_stale_peers(self) -> List[bytes]:
        """Return validator_ids of peers that have not been seen within timeout."""
        now = time.time()
        return [
            vid for vid, peer in self.peers.items()
            if now - peer.last_seen > HEARTBEAT_TIMEOUT
        ]

    def encode_peer_list(self) -> bytes:
        """Serialize our peer list for PEER_LIST messages."""
        parts = []
        for peer in self.peers.values():
            host, port_s = peer.address.rsplit(":", 1)
            port = int(port_s)
            host_bytes = host.encode("utf-8")
            # [2-byte host_len][host][2-byte port][32-byte validator_id][4-byte zone_id][8-byte stake]
            parts.append(struct.pack(">H", len(host_bytes)))
            parts.append(host_bytes)
            parts.append(struct.pack(">H", port))
            parts.append(peer.validator_id)
            parts.append(struct.pack(">iQ", peer.zone_id, peer.stake))
        return b"".join(parts)

    def decode_peer_list(self, data: bytes) -> List[dict]:
        """Deserialize a PEER_LIST payload into peer dicts."""
        results = []
        offset = 0
        while offset < len(data):
            if offset + 2 > len(data):
                break
            host_len = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            host = data[offset:offset+host_len].decode("utf-8")
            offset += host_len
            port = struct.unpack(">H", data[offset:offset+2])[0]
            offset += 2
            validator_id = data[offset:offset+32]
            offset += 32
            zone_id, stake = struct.unpack(">iQ", data[offset:offset+12])
            offset += 12
            results.append({
                "host": host,
                "port": port,
                "validator_id": validator_id,
                "zone_id": zone_id,
                "stake": stake,
                "address": f"{host}:{port}",
            })
        return results

    def encode_self_info(self, listen_port: int) -> bytes:
        """Encode our own info for PEER_DISCOVERY handshake."""
        # [32-byte validator_id][4-byte zone_id][8-byte stake][2-byte listen_port]
        return self.validator_id + struct.pack(">iQH", self.zone_id, self.stake, listen_port)

    @staticmethod
    def decode_self_info(data: bytes) -> dict:
        """Decode a PEER_DISCOVERY payload."""
        validator_id = data[:32]
        zone_id, stake, listen_port = struct.unpack(">iQH", data[32:46])
        return {
            "validator_id": validator_id,
            "zone_id": zone_id,
            "stake": stake,
            "listen_port": listen_port,
        }


# =============================================================================
# P2P NODE
# =============================================================================

class P2PNode:
    """
    asyncio TCP P2P node for QRTB.

    Usage:
        node = P2PNode(validator_id, zone_id, stake)
        node.on_message = my_handler   # async def handler(peer_id, msg_type, payload)
        await node.start("0.0.0.0", 9000)
        await node.connect_to_peer("1.2.3.4", 9000)
        await node.broadcast(MessageType.TX_BROADCAST, tx_bytes)
    """

    def __init__(self, validator_id: bytes, zone_id: int, stake: int):
        self.peer_manager = PeerManager(validator_id, zone_id, stake)
        self.validator_id = validator_id

        self._server: Optional[asyncio.Server] = None
        self._host: str = ""
        self._port: int = 0

        # User-supplied message handler
        self._message_handler: Optional[Callable] = None

        # Background tasks we need to cancel on shutdown
        self._tasks: List[asyncio.Task] = []

        self._running = False

    # -- callback registration ------------------------------------------------

    @property
    def on_message(self) -> Optional[Callable]:
        return self._message_handler

    @on_message.setter
    def on_message(self, handler: Callable) -> None:
        """
        Register a message callback.

        Signature: async def handler(peer_id: bytes, msg_type: MessageType, payload: bytes)
        """
        self._message_handler = handler

    # -- lifecycle ------------------------------------------------------------

    async def start(self, host: str, port: int) -> None:
        """Start the TCP listener and heartbeat loop."""
        self._host = host
        self._port = port
        self._running = True

        self._server = await asyncio.start_server(
            self._handle_inbound, host, port
        )
        logger.info("P2P listening on %s:%d", host, port)

        # Start heartbeat background task
        task = asyncio.ensure_future(self._heartbeat_loop())
        self._tasks.append(task)

    async def stop(self) -> None:
        """Shut down the node."""
        self._running = False

        # Cancel background tasks
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()

        # Close all peer writers
        for peer in list(self.peer_manager.peers.values()):
            await self._close_peer(peer.validator_id)

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    # -- outbound connections -------------------------------------------------

    async def connect_to_peer(self, host: str, port: int) -> bool:
        """
        Initiate outbound connection to a peer.
        Returns True on success.
        """
        if not self.peer_manager.can_accept_peer():
            logger.warning("At max peers (%d), rejecting outbound to %s:%d",
                           MAX_PEERS, host, port)
            return False

        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            logger.debug("Failed to connect to %s:%d: %s", host, port, exc)
            return False

        # Send our PEER_DISCOVERY handshake
        info_payload = self.peer_manager.encode_self_info(self._port)
        writer.write(encode_message(MessageType.PEER_DISCOVERY, info_payload))
        await writer.drain()

        # Read their handshake
        try:
            msg_type, payload = await asyncio.wait_for(
                read_message(reader), timeout=10.0
            )
        except Exception:
            writer.close()
            return False

        if msg_type != MessageType.PEER_DISCOVERY:
            writer.close()
            return False

        remote_info = PeerManager.decode_self_info(payload)
        remote_vid = remote_info["validator_id"]

        if remote_vid == self.validator_id:
            writer.close()
            return False

        peer = PeerConnection(
            validator_id=remote_vid,
            address=f"{host}:{remote_info['listen_port']}",
            zone_id=remote_info["zone_id"],
            stake=remote_info["stake"],
            last_seen=time.time(),
            reader=reader,
            writer=writer,
            outbound=True,
        )

        if not self.peer_manager.add_peer(peer):
            writer.close()
            return False

        logger.info("Connected to peer %s at %s", remote_vid.hex()[:8], peer.address)

        # Exchange peer lists
        await self._exchange_peer_lists(peer)

        # Start reading loop for this connection
        task = asyncio.ensure_future(self._read_loop(peer))
        self._tasks.append(task)

        return True

    # -- inbound connection handler -------------------------------------------

    async def _handle_inbound(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle a new inbound TCP connection."""
        if not self.peer_manager.can_accept_peer():
            writer.close()
            return

        # Expect PEER_DISCOVERY handshake
        try:
            msg_type, payload = await asyncio.wait_for(
                read_message(reader), timeout=10.0
            )
        except Exception:
            writer.close()
            return

        if msg_type != MessageType.PEER_DISCOVERY:
            writer.close()
            return

        remote_info = PeerManager.decode_self_info(payload)
        remote_vid = remote_info["validator_id"]

        if remote_vid == self.validator_id:
            writer.close()
            return

        # Already connected to this peer
        if remote_vid in self.peer_manager.peers:
            writer.close()
            return

        # Respond with our own PEER_DISCOVERY
        info_payload = self.peer_manager.encode_self_info(self._port)
        writer.write(encode_message(MessageType.PEER_DISCOVERY, info_payload))
        await writer.drain()

        peername = writer.get_extra_info("peername")
        remote_host = peername[0] if peername else "unknown"

        peer = PeerConnection(
            validator_id=remote_vid,
            address=f"{remote_host}:{remote_info['listen_port']}",
            zone_id=remote_info["zone_id"],
            stake=remote_info["stake"],
            last_seen=time.time(),
            reader=reader,
            writer=writer,
            outbound=False,
        )

        if not self.peer_manager.add_peer(peer):
            writer.close()
            return

        logger.info("Accepted peer %s from %s", remote_vid.hex()[:8], peer.address)

        # Exchange peer lists
        await self._exchange_peer_lists(peer)

        # Start reading loop
        task = asyncio.ensure_future(self._read_loop(peer))
        self._tasks.append(task)

    # -- read loop ------------------------------------------------------------

    async def _read_loop(self, peer: PeerConnection) -> None:
        """Read messages from a peer until disconnect."""
        try:
            while self._running and peer.reader:
                msg_type, payload = await asyncio.wait_for(
                    read_message(peer.reader), timeout=HEARTBEAT_TIMEOUT + 30
                )
                self.peer_manager.touch_peer(peer.validator_id)
                await self._dispatch(peer.validator_id, msg_type, payload)
        except (asyncio.IncompleteReadError, ConnectionError, asyncio.TimeoutError, OSError):
            pass
        except asyncio.CancelledError:
            return
        finally:
            await self._close_peer(peer.validator_id)

    async def _dispatch(
        self, peer_id: bytes, msg_type: MessageType, payload: bytes
    ) -> None:
        """Route a received message."""
        if msg_type == MessageType.PING:
            await self.send_to(peer_id, MessageType.PONG, b"")
            return

        if msg_type == MessageType.PONG:
            # Just touching last_seen (already done above) is sufficient
            return

        if msg_type == MessageType.PEER_LIST:
            entries = self.peer_manager.decode_peer_list(payload)
            for entry in entries:
                addr = entry["address"]
                self.peer_manager.known_addresses.add(addr)
            return

        # Delegate everything else to the user handler
        if self._message_handler:
            try:
                await self._message_handler(peer_id, msg_type, payload)
            except Exception:
                logger.exception("Error in message handler for type %s", msg_type)

    # -- peer list exchange ---------------------------------------------------

    async def _exchange_peer_lists(self, peer: PeerConnection) -> None:
        """Send our peer list to a newly connected peer."""
        try:
            pl_payload = self.peer_manager.encode_peer_list()
            await self._send_raw(peer, MessageType.PEER_LIST, pl_payload)
        except Exception:
            pass

    # -- sending --------------------------------------------------------------

    async def broadcast(self, msg_type: MessageType, payload: bytes) -> int:
        """
        Send a message to all connected peers.
        Returns the number of peers it was sent to.
        """
        sent = 0
        for vid in list(self.peer_manager.peers.keys()):
            try:
                await self.send_to(vid, msg_type, payload)
                sent += 1
            except Exception:
                pass
        return sent

    async def send_to(
        self, peer_id: bytes, msg_type: MessageType, payload: bytes
    ) -> None:
        """Send a message to a specific peer by validator_id."""
        peer = self.peer_manager.get_peer(peer_id)
        if peer is None:
            raise KeyError(f"Peer {peer_id.hex()[:8]} not connected")
        await self._send_raw(peer, msg_type, payload)

    async def _send_raw(
        self, peer: PeerConnection, msg_type: MessageType, payload: bytes
    ) -> None:
        """Low-level send with framing."""
        if peer.writer is None or peer.writer.is_closing():
            raise ConnectionError("Writer closed")
        data = encode_message(msg_type, payload)
        peer.writer.write(data)
        await peer.writer.drain()

    # -- peer cleanup ---------------------------------------------------------

    async def _close_peer(self, validator_id: bytes) -> None:
        """Disconnect and remove a peer."""
        peer = self.peer_manager.remove_peer(validator_id)
        if peer and peer.writer and not peer.writer.is_closing():
            try:
                peer.writer.close()
                await peer.writer.wait_closed()
            except Exception:
                pass

    # -- heartbeat ------------------------------------------------------------

    async def _heartbeat_loop(self) -> None:
        """Periodically PING all peers and prune stale ones."""
        try:
            while self._running:
                await asyncio.sleep(HEARTBEAT_INTERVAL)

                # Send PING to all peers
                for vid in list(self.peer_manager.peers.keys()):
                    try:
                        await self.send_to(vid, MessageType.PING, b"")
                    except Exception:
                        pass

                # Prune stale peers
                stale = self.peer_manager.get_stale_peers()
                for vid in stale:
                    logger.info("Pruning stale peer %s", vid.hex()[:8])
                    await self._close_peer(vid)

        except asyncio.CancelledError:
            return

    # -- bootstrap ------------------------------------------------------------

    async def bootstrap(self) -> int:
        """Connect to all seed nodes. Returns number of successful connections."""
        connected = 0
        for host, port in self.peer_manager.seed_nodes:
            if self.peer_manager.peer_count >= MAX_PEERS:
                break
            ok = await self.connect_to_peer(host, port)
            if ok:
                connected += 1
        return connected

    # -- status ---------------------------------------------------------------

    def get_status(self) -> dict:
        return {
            "validator_id": self.validator_id.hex()[:16],
            "listening": f"{self._host}:{self._port}",
            "peers": self.peer_manager.peer_count,
            "known_addresses": len(self.peer_manager.known_addresses),
            "running": self._running,
        }
