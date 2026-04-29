"""
QRTB Runnable Validator Node
- Ties P2P networking, measurement, consensus, and storage together
- Epoch orchestration with real RTT over TCP
- Replaces simulation message passing with real P2P
"""

import asyncio
import json
import time
import struct
import logging
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .crypto import sha3_256, secure_random
from .p2p import P2PNode, PeerManager, MessageType
from .validator import ValidatorNode, ValidatorConfig, ValidatorState
from .measurement import (
    MeasurementProtocol, PeerInfo, RTTMeasurement, RealRTTMeasurement,
    MeasurementCommitment, MeasurementReveal,
    haversine_distance_km, theoretical_rtt_ms,
)
from .epoch import EpochManager, EpochPhase
from .consensus import BFTConsensus, ConsensusProposal, ConsensusVote, ConsensusBlock
from .block_producer import BlockProducer
from .transaction import UTXOSet, Mempool, AuthRegistry, TransactionValidator
from .storage import StorageManager

logger = logging.getLogger("qrtb.node")


# =============================================================================
# NODE CONFIG
# =============================================================================

@dataclass
class NodeConfig:
    """Configuration for a QRTB node."""
    host: str = "0.0.0.0"
    port: int = 9000
    zone_id: int = 0
    stake: int = 1000
    location: Optional[Tuple[float, float]] = None
    seed_nodes: List[Tuple[str, int]] = field(default_factory=list)
    data_dir: Optional[str] = None      # None -> temp dir
    use_real_measurements: bool = True


# =============================================================================
# NODE
# =============================================================================

class Node:
    """
    Full QRTB validator node.

    Orchestrates:
      - P2P networking (TCP)
      - Measurement (real RTT via TCP connect timing)
      - BFT Consensus (broadcast proposals/votes via P2P)
      - Block production and storage
    """

    def __init__(self, config: NodeConfig):
        self.config = config

        # Validator identity
        self.validator_id = secure_random(32)

        # Validator subsystem (reuses existing ValidatorNode for state/logic)
        self.validator_config = ValidatorConfig(
            zone_id=config.zone_id,
            stake=config.stake,
            location=config.location,
        )
        self.validator = ValidatorNode(self.validator_config)
        # Override the auto-generated validator_id with ours
        self.validator.validator_id = self.validator_id
        self.validator.measurement_protocol.validator_id = self.validator_id
        self.validator.consensus.validator_id = self.validator_id
        # Re-register self in consensus with our id
        self.validator.consensus.validators.clear()
        self.validator.consensus.total_stake = 0
        self.validator.consensus.register_validator(self.validator_id, config.stake)

        # P2P layer
        self.p2p = P2PNode(self.validator_id, config.zone_id, config.stake)
        self.p2p.on_message = self._handle_message

        # Seed nodes
        self.p2p.peer_manager.add_seed_nodes(config.seed_nodes)

        # RTT measurement
        self.rtt_measurer = RealRTTMeasurement()

        # Epoch management (shared with validator)
        self.epoch_manager = self.validator.epoch_manager

        # Storage
        data_dir = config.data_dir or tempfile.mkdtemp(prefix="qrtb_node_")
        self.storage = StorageManager(data_dir)

        # Transaction layer
        self.utxo_set = UTXOSet()
        self.mempool = Mempool()
        self.auth_registry = AuthRegistry()
        self.tx_validator = TransactionValidator(self.utxo_set, self.auth_registry)

        # Block producer
        self.block_producer = BlockProducer(
            self.validator_id, self.utxo_set, self.mempool
        )

        # Consensus state for current epoch
        self._received_commitments: Dict[bytes, bytes] = {}   # vid -> serialized
        self._received_reveals: Dict[bytes, bytes] = {}        # vid -> serialized
        self._received_proposals: Dict[bytes, bytes] = {}      # hash -> serialized
        self._received_votes: List[bytes] = []

        self._running = False

        # Map peer validator_ids to their P2P listen addresses for RTT probing
        self._peer_addresses: Dict[bytes, Tuple[str, int]] = {}

    # =========================================================================
    # LIFECYCLE
    # =========================================================================

    async def start(self) -> None:
        """Start the node: P2P listener, seed connections, epoch loop."""
        self._running = True

        # Start P2P
        await self.p2p.start(self.config.host, self.config.port)

        # Bootstrap from seed nodes
        connected = await self.p2p.bootstrap()
        logger.info("Bootstrapped to %d seed nodes", connected)

        # Register peers from P2P into the validator subsystem
        self._sync_peers_from_p2p()

        logger.info("Node started: %s on %s:%d",
                     self.validator_id.hex()[:8],
                     self.config.host, self.config.port)

    async def stop(self) -> None:
        """Shut down cleanly."""
        self._running = False
        await self.p2p.stop()
        self.storage.close()

    # =========================================================================
    # EPOCH ORCHESTRATION
    # =========================================================================

    async def run_epoch(self) -> Optional[ConsensusBlock]:
        """
        Orchestrate one full epoch:
          1. Measurement phase (real RTT via P2P)
          2. Commit-reveal
          3. Consensus (broadcast proposals/votes via P2P)
          4. Finalization
        """
        epoch = self.epoch_manager.get_current_epoch()
        self.validator.start_epoch(epoch)
        self._sync_peers_from_p2p()

        logger.info("Epoch %d: measurement phase", epoch)

        # ----- Measurement Phase -----
        measurements = await self._measure_peers()
        self.validator.current_measurements = measurements
        self.validator.measurement_protocol.measurements = measurements
        self.validator.stats.measurements_made += len(measurements)

        # Create and broadcast commitment
        commitment = self.validator.create_measurement_commitment()
        if commitment:
            payload = self._serialize_commitment(commitment)
            await self.p2p.broadcast(MessageType.MEASUREMENT_COMMIT, payload)

        # Brief wait for peer commitments
        await asyncio.sleep(2.0)

        # Reveal
        reveal = self.validator.create_reveal()
        reveal_payload = self._serialize_reveal(reveal)
        await self.p2p.broadcast(MessageType.MEASUREMENT_REVEAL, reveal_payload)

        # Brief wait for peer reveals
        await asyncio.sleep(2.0)

        logger.info("Epoch %d: consensus phase", epoch)

        # ----- Consensus Phase -----
        all_measurements = self.validator.measurement_protocol.get_all_measurements()
        locations = {self.validator_id: self.validator_config.location}
        for vid, peer in self.validator.peers.items():
            locations[vid] = peer.config.location

        # Check if we are proposer
        block = None
        if self.validator.consensus.am_i_proposer():
            logger.info("Epoch %d: I am proposer", epoch)
            proposal = self.validator.consensus.create_proposal(
                measurements=all_measurements,
                locations=locations,
            )
            self.validator.stats.blocks_proposed += 1
            await self.p2p.broadcast(
                MessageType.PROPOSAL, self._serialize_proposal(proposal)
            )

            # Self pre-vote
            vote = self.validator.consensus.create_pre_vote(proposal.proposal_hash)
            await self.p2p.broadcast(
                MessageType.PRE_VOTE, self._serialize_vote(vote)
            )
            self.validator.stats.votes_cast += 1

            # Wait for votes
            await asyncio.sleep(3.0)

            # Try pre-commit
            commit_vote = self.validator.consensus.create_pre_commit(
                proposal.proposal_hash
            )
            if commit_vote:
                await self.p2p.broadcast(
                    MessageType.PRE_COMMIT, self._serialize_vote(commit_vote)
                )
                self.validator.stats.votes_cast += 1

            await asyncio.sleep(2.0)

            # Try finalize
            block = self.validator.consensus.try_finalize(proposal.proposal_hash)
        else:
            # Non-proposer: wait for proposal, then vote
            await asyncio.sleep(5.0)

            # Try finalize whatever proposal we have
            for phash in list(self.validator.consensus.received_proposals.keys()):
                block = self.validator.consensus.try_finalize(phash)
                if block:
                    break

        if block:
            self.validator.on_block_finalized(block)
            await self.p2p.broadcast(
                MessageType.BLOCK, self._serialize_block_hash(block)
            )
            logger.info("Epoch %d finalized: %s", epoch, block.block_hash.hex()[:16])

        return block

    async def run_loop(self, num_epochs: int = 0) -> None:
        """
        Run the epoch loop.

        If num_epochs is 0, run indefinitely.
        """
        count = 0
        while self._running:
            await self.run_epoch()
            count += 1
            if num_epochs > 0 and count >= num_epochs:
                break

    # =========================================================================
    # REAL RTT MEASUREMENT
    # =========================================================================

    async def _measure_peers(self) -> List[RTTMeasurement]:
        """
        Measure RTT to selected peers using real TCP connect timing.
        Falls back to simulated measurements if TCP probe fails.
        """
        self.validator.measurement_protocol.select_targets()
        targets = self.validator.measurement_protocol.selected_targets
        results: List[RTTMeasurement] = []
        timestamp = int(time.time() * 1000)

        for target_id in targets:
            peer_info = self.validator.measurement_protocol.peers.get(target_id)
            if peer_info is None:
                continue

            # Try real RTT first using P2P address
            real_rtt = None
            addr = self._peer_addresses.get(target_id)
            if addr and self.config.use_real_measurements:
                try:
                    real_rtt = await self.rtt_measurer.measure_rtt(addr[0], addr[1])
                except ConnectionError:
                    pass

            # Calculate theoretical for reference
            distance = haversine_distance_km(
                self.validator_config.location, peer_info.location
            )
            theoretical = theoretical_rtt_ms(distance)

            if real_rtt is not None:
                actual_ms = real_rtt
            else:
                # Fallback to simulation
                from .measurement import simulate_rtt
                actual_ms = simulate_rtt(
                    theoretical,
                    is_adversary=self.validator_config.is_adversary,
                )

            measurement = RTTMeasurement(
                source_id=self.validator_id,
                target_id=target_id,
                rtt_ms=actual_ms,
                timestamp=timestamp,
                theoretical_rtt_ms=theoretical,
            )
            results.append(measurement)

        return results

    # =========================================================================
    # P2P MESSAGE HANDLING
    # =========================================================================

    async def _handle_message(
        self, peer_id: bytes, msg_type: MessageType, payload: bytes
    ) -> None:
        """Dispatch inbound P2P messages to the validator subsystem."""

        if msg_type == MessageType.MEASUREMENT_COMMIT:
            commitment = self._deserialize_commitment(payload)
            if commitment:
                self.validator.receive_commitment(commitment)

        elif msg_type == MessageType.MEASUREMENT_REVEAL:
            reveal = self._deserialize_reveal(payload)
            if reveal:
                self.validator.receive_reveal(reveal)

        elif msg_type == MessageType.PROPOSAL:
            proposal = self._deserialize_proposal(payload)
            if proposal:
                valid, reason = self.validator.receive_proposal(proposal)
                if valid:
                    # Auto pre-vote
                    vote = self.validator.consensus.create_pre_vote(
                        proposal.proposal_hash
                    )
                    await self.p2p.broadcast(
                        MessageType.PRE_VOTE, self._serialize_vote(vote)
                    )
                    self.validator.stats.votes_cast += 1

        elif msg_type == MessageType.PRE_VOTE:
            vote = self._deserialize_vote(payload, "pre-vote")
            if vote:
                self.validator.receive_vote(vote)

        elif msg_type == MessageType.PRE_COMMIT:
            vote = self._deserialize_vote(payload, "pre-commit")
            if vote:
                self.validator.receive_vote(vote)

        elif msg_type == MessageType.TX_BROADCAST:
            # Future: deserialize and add to mempool
            pass

        elif msg_type == MessageType.EPOCH_SYNC:
            # Future: epoch synchronization
            pass

        elif msg_type == MessageType.BLOCK:
            # Future: block sync
            pass

    # =========================================================================
    # PEER SYNC
    # =========================================================================

    def _sync_peers_from_p2p(self) -> None:
        """
        Register P2P-connected peers into the validator's peer registry
        and consensus engine so they participate in measurements and voting.
        """
        for vid, conn in self.p2p.peer_manager.peers.items():
            if vid not in self.validator.peers:
                # Create a minimal ValidatorNode stand-in for measurement info
                peer_info = PeerInfo(
                    validator_id=vid,
                    location=(0.0, 0.0),  # Unknown until they tell us
                    zone_id=conn.zone_id,
                    stake=conn.stake,
                    last_seen=conn.last_seen,
                )
                self.validator.measurement_protocol.add_peer(peer_info)
                self.validator.consensus.register_validator(vid, conn.stake)

            # Track the address for RTT probing
            try:
                host, port_s = conn.address.rsplit(":", 1)
                self._peer_addresses[vid] = (host, int(port_s))
            except (ValueError, AttributeError):
                pass

    # =========================================================================
    # SERIALIZATION HELPERS
    # =========================================================================
    # These are minimal wire-format helpers for shipping consensus objects
    # over P2P. Full production serialization would use protobuf or similar.

    def _serialize_commitment(self, c: MeasurementCommitment) -> bytes:
        """Serialize a MeasurementCommitment for P2P."""
        parts = [
            c.validator_id,                                     # 32
            struct.pack(">Q", c.epoch),                         # 8
            struct.pack(">I", len(c.target_ids)),               # 4
        ]
        for tid in c.target_ids:
            parts.append(tid)                                   # 32 each
        parts.append(c.commitment_hash)                         # 32
        parts.append(struct.pack(">Q", c.timestamp))            # 8
        return b"".join(parts)

    def _deserialize_commitment(self, data: bytes) -> Optional[MeasurementCommitment]:
        try:
            off = 0
            validator_id = data[off:off+32]; off += 32
            epoch = struct.unpack(">Q", data[off:off+8])[0]; off += 8
            num_targets = struct.unpack(">I", data[off:off+4])[0]; off += 4
            target_ids = []
            for _ in range(num_targets):
                target_ids.append(data[off:off+32]); off += 32
            commitment_hash = data[off:off+32]; off += 32
            timestamp = struct.unpack(">Q", data[off:off+8])[0]; off += 8
            return MeasurementCommitment(
                validator_id=validator_id,
                epoch=epoch,
                target_ids=target_ids,
                commitment_hash=commitment_hash,
                timestamp=timestamp,
            )
        except Exception:
            return None

    def _serialize_reveal(self, r: MeasurementReveal) -> bytes:
        """Serialize a MeasurementReveal for P2P (simplified)."""
        # For now, send commitment + measurement count + each measurement's to_bytes
        parts = [
            r.validator_id,
            struct.pack(">Q", r.epoch),
            struct.pack(">I", len(r.measurements)),
        ]
        for m in r.measurements:
            mb = m.to_bytes()
            parts.append(struct.pack(">I", len(mb)))
            parts.append(mb)
        # Append commitment
        cdata = self._serialize_commitment(r.commitment)
        parts.append(struct.pack(">I", len(cdata)))
        parts.append(cdata)
        return b"".join(parts)

    def _deserialize_reveal(self, data: bytes) -> Optional[MeasurementReveal]:
        """Deserialize -- simplified, skips full reconstruction."""
        # In production you would fully reconstruct. For now we store raw
        # and let the validator process the commitment it already received.
        return None  # Handled via receive_reveal direct path for local testing

    def _serialize_proposal(self, p: ConsensusProposal) -> bytes:
        parts = [
            p.proposer_id,                                      # 32
            struct.pack(">QI", p.epoch, p.round),               # 12
            p.measurement_root,                                 # 32
            p.transaction_root if p.transaction_root else b"\x00" * 32,
            p.state_root if p.state_root else b"\x00" * 32,
            struct.pack(">Q", p.timestamp),                     # 8
        ]
        return b"".join(parts)

    def _deserialize_proposal(self, data: bytes) -> Optional[ConsensusProposal]:
        try:
            off = 0
            proposer_id = data[off:off+32]; off += 32
            epoch, rnd = struct.unpack(">QI", data[off:off+12]); off += 12
            measurement_root = data[off:off+32]; off += 32
            transaction_root = data[off:off+32]; off += 32
            state_root = data[off:off+32]; off += 32
            timestamp = struct.unpack(">Q", data[off:off+8])[0]; off += 8
            return ConsensusProposal(
                proposer_id=proposer_id,
                epoch=epoch,
                round=rnd,
                measurement_root=measurement_root,
                transaction_root=transaction_root,
                state_root=state_root,
                timestamp=timestamp,
            )
        except Exception:
            return None

    def _serialize_vote(self, v: ConsensusVote) -> bytes:
        parts = [
            v.voter_id,                                         # 32
            struct.pack(">QI", v.epoch, v.round),               # 12
            v.proposal_hash,                                    # 32
            struct.pack(">Q", v.stake),                         # 8
            struct.pack(">Q", v.timestamp),                     # 8
        ]
        return b"".join(parts)

    def _deserialize_vote(self, data: bytes, vote_type: str) -> Optional[ConsensusVote]:
        try:
            off = 0
            voter_id = data[off:off+32]; off += 32
            epoch, rnd = struct.unpack(">QI", data[off:off+12]); off += 12
            proposal_hash = data[off:off+32]; off += 32
            stake = struct.unpack(">Q", data[off:off+8])[0]; off += 8
            timestamp = struct.unpack(">Q", data[off:off+8])[0]; off += 8
            return ConsensusVote(
                voter_id=voter_id,
                epoch=epoch,
                round=rnd,
                proposal_hash=proposal_hash,
                vote_type=vote_type,
                stake=stake,
                timestamp=timestamp,
            )
        except Exception:
            return None

    def _serialize_block_hash(self, block: ConsensusBlock) -> bytes:
        return block.block_hash

    # =========================================================================
    # STATUS
    # =========================================================================

    def get_status(self) -> dict:
        return {
            "node": {
                "validator_id": self.validator_id.hex()[:16],
                "zone_id": self.config.zone_id,
                "stake": self.config.stake,
                "host": self.config.host,
                "port": self.config.port,
            },
            "p2p": self.p2p.get_status(),
            "validator": self.validator.get_status(),
            "storage": self.storage.get_chain_info(),
        }
