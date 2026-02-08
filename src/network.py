"""
QRTB Network Simulation
- Multi-validator testnet
- Message routing
- Epoch coordination
- Adversary simulation
"""

import time
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
import statistics

from .validator import ValidatorNode, ValidatorConfig, ValidatorState
from .measurement import ZONE_LOCATIONS, haversine_distance_km, theoretical_rtt_ms
from .consensus import ConsensusBlock
from .detection import aggregate_detection_results

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

@dataclass
class NetworkConfig:
    """Configuration for the test network"""
    num_zones: int = 6
    validators_per_zone: int = 5
    shards_per_zone: int = 1  # Simplified for testnet
    base_stake: int = 1000
    adversary_percentage: float = 0.1  # 10% adversaries
    message_delay_ms: float = 50.0  # Simulated network delay


# =============================================================================
# NETWORK SIMULATION
# =============================================================================

class QRTBTestnet:
    """
    Simulated QRTB testnet with multiple validators
    """
    
    def __init__(self, config: NetworkConfig):
        self.config = config
        self.genesis_time = time.time()
        
        # Validators by ID
        self.validators: Dict[bytes, ValidatorNode] = {}
        
        # Zone organization
        self.zones: Dict[int, List[bytes]] = defaultdict(list)
        
        # Message queue: (delivery_time, sender, target, msg_type, data)
        self.message_queue: List[Tuple[float, bytes, bytes, str, any]] = []
        
        # Finalized blocks
        self.finalized_blocks: Dict[int, ConsensusBlock] = {}
        
        # Statistics
        self.epoch_stats: Dict[int, dict] = {}
        
        # Logging
        self.verbose = True
    
    def log(self, message: str) -> None:
        """Log a message"""
        if self.verbose:
            print(f"[NETWORK] {message}")
    
    # =========================================================================
    # NETWORK SETUP
    # =========================================================================
    
    def initialize_network(self) -> None:
        """Create all validators and establish connections"""
        self.log(f"Initializing network with {self.config.num_zones} zones, "
                f"{self.config.validators_per_zone} validators each")
        
        total_validators = self.config.num_zones * self.config.validators_per_zone
        num_adversaries = int(total_validators * self.config.adversary_percentage)
        adversary_indices = set(random.sample(range(total_validators), num_adversaries))
        
        validator_index = 0
        
        for zone_id in range(self.config.num_zones):
            for i in range(self.config.validators_per_zone):
                is_adversary = validator_index in adversary_indices
                
                config = ValidatorConfig(
                    zone_id=zone_id,
                    stake=self.config.base_stake + random.randint(-200, 200),
                    is_adversary=is_adversary
                )
                
                node = ValidatorNode(config, genesis_time=self.genesis_time)
                node.log_callback = lambda msg, vid=node.validator_id: None  # Quiet
                
                self.validators[node.validator_id] = node
                self.zones[zone_id].append(node.validator_id)
                
                validator_index += 1
        
        # Connect all validators as peers
        self._connect_validators()
        
        self.log(f"Created {len(self.validators)} validators "
                f"({num_adversaries} adversaries)")
    
    def _connect_validators(self) -> None:
        """Establish peer connections between all validators"""
        validator_list = list(self.validators.values())
        
        for node in validator_list:
            for peer in validator_list:
                if peer.validator_id != node.validator_id:
                    node.add_peer(peer)
    
    # =========================================================================
    # MESSAGE ROUTING
    # =========================================================================
    
    def _calculate_delay(self, sender: ValidatorNode, target: ValidatorNode) -> float:
        """Calculate message delay based on distance"""
        distance = haversine_distance_km(
            sender.config.location,
            target.config.location
        )
        # Delay = half RTT (one-way)
        theoretical = theoretical_rtt_ms(distance) / 2
        # Add jitter
        actual = theoretical * random.gauss(1.0, 0.1)
        return max(self.config.message_delay_ms, actual)
    
    def _route_messages(self) -> None:
        """Collect and route all outbound messages"""
        for node in self.validators.values():
            messages = node.deliver_outbox()
            
            for msg_type, target_id, data in messages:
                target = self.validators.get(target_id)
                if target is None:
                    continue
                
                delay = self._calculate_delay(node, target)
                delivery_time = time.time() + (delay / 1000)
                
                self.message_queue.append((
                    delivery_time,
                    node.validator_id,
                    target_id,
                    msg_type,
                    data
                ))
        
        # Sort by delivery time
        self.message_queue.sort(key=lambda x: x[0])
    
    def _deliver_messages(self) -> int:
        """Deliver messages that are ready"""
        delivered = 0
        now = time.time()
        
        while self.message_queue and self.message_queue[0][0] <= now:
            _, sender_id, target_id, msg_type, data = self.message_queue.pop(0)
            
            target = self.validators.get(target_id)
            if target:
                target.inbox.append((msg_type, data))
                delivered += 1
        
        return delivered
    
    def _process_all_inboxes(self) -> None:
        """Process all validator inboxes"""
        for node in self.validators.values():
            node.process_inbox()
    
    # =========================================================================
    # EPOCH SIMULATION
    # =========================================================================
    
    def run_epoch(self, epoch: int) -> dict:
        """Run a complete epoch simulation"""
        self.log(f"\n{'='*60}")
        self.log(f"EPOCH {epoch}")
        self.log(f"{'='*60}")
        
        epoch_start = time.time()
        
        # Phase 1: Start epoch on all validators
        for node in self.validators.values():
            node.start_epoch(epoch)
        
        # Phase 2: Measurement
        self.log("Phase: MEASUREMENT")
        for node in self.validators.values():
            node.run_measurement_phase()
            node.create_measurement_commitment()
        
        # Phase 3: Broadcast commitments - direct delivery for simulation
        self.log("Phase: COMMIT")
        for node in self.validators.values():
            if node.current_commitment:
                for peer in self.validators.values():
                    if peer.validator_id != node.validator_id:
                        peer.receive_commitment(node.current_commitment)
        
        # Phase 4: Reveal - direct delivery
        self.log("Phase: REVEAL")
        for node in self.validators.values():
            reveal = node.create_reveal()
            for peer in self.validators.values():
                if peer.validator_id != node.validator_id:
                    peer.receive_reveal(reveal)
        
        # Phase 5: Consensus
        self.log("Phase: CONSENSUS")
        
        # Collect all measurements from all validators
        all_measurements = {}
        for node in self.validators.values():
            all_measurements[node.validator_id] = node.current_measurements
        
        locations = {
            vid: self.validators[vid].config.location 
            for vid in self.validators
        }
        
        # Find proposer and create proposal
        proposer = None
        proposal = None
        
        for node in self.validators.values():
            if node.consensus.am_i_proposer():
                proposer = node
                proposal = node.consensus.create_proposal(
                    measurements=all_measurements,
                    locations=locations
                )
                break
        
        if proposer is None:
            # Fallback: first validator proposes
            proposer = list(self.validators.values())[0]
            proposal = proposer.consensus.create_proposal(
                measurements=all_measurements,
                locations=locations
            )
        
        if proposer:
            self.log(f"Proposer: {proposer.validator_id.hex()[:8]}")
        
        # Broadcast proposal to all validators
        for node in self.validators.values():
            if node.validator_id != proposer.validator_id:
                node.consensus.receive_proposal(proposal)
        
        # All validators pre-vote
        all_votes = []
        for node in self.validators.values():
            vote = node.consensus.create_pre_vote(proposal.proposal_hash)
            all_votes.append(vote)
        
        # Distribute pre-votes
        for vote in all_votes:
            for node in self.validators.values():
                if node.validator_id != vote.voter_id:
                    node.consensus.receive_pre_vote(vote)
        
        # Check pre-vote threshold and pre-commit
        pre_commits = []
        for node in self.validators.values():
            commit = node.consensus.create_pre_commit(proposal.proposal_hash)
            if commit:
                pre_commits.append(commit)
        
        # Distribute pre-commits
        for vote in pre_commits:
            for node in self.validators.values():
                if node.validator_id != vote.voter_id:
                    node.consensus.receive_pre_commit(vote)
        
        # Try to finalize
        finalized_block = None
        for node in self.validators.values():
            block = node.consensus.try_finalize(proposal.proposal_hash)
            if block:
                finalized_block = block
                self.finalized_blocks[epoch] = block
                break
        
        epoch_duration = time.time() - epoch_start
        
        # Collect statistics
        stats = self._collect_epoch_stats(epoch, finalized_block, epoch_duration)
        self.epoch_stats[epoch] = stats
        
        self._print_epoch_summary(epoch, stats)
        
        return stats
    
    def _collect_epoch_stats(self, epoch: int, block: Optional[ConsensusBlock], 
                            duration: float) -> dict:
        """Collect statistics for the epoch"""
        # Count adversaries detected
        adversaries_detected = 0
        false_positives = 0
        
        # Count actual adversaries
        total_adversaries = sum(
            1 for n in self.validators.values() if n.config.is_adversary
        )
        total_honest = len(self.validators) - total_adversaries
        
        if block and block.proposal.detection_results:
            for vid, result in block.proposal.detection_results.items():
                node = self.validators.get(vid)
                if node:
                    if result.is_suspicious:
                        if node.config.is_adversary:
                            adversaries_detected += 1
                        else:
                            false_positives += 1
        
        # Voting stats
        total_stake = sum(n.config.stake for n in self.validators.values())
        supporting_stake = block.supporting_stake if block else 0
        
        return {
            "epoch": epoch,
            "finalized": block is not None,
            "duration_ms": duration * 1000,
            "validators": len(self.validators),
            "adversaries": total_adversaries,
            "honest": total_honest,
            "adversaries_detected": adversaries_detected,
            "false_positives": false_positives,
            "detection_rate": adversaries_detected / max(total_adversaries, 1),
            "false_positive_rate": false_positives / max(total_honest, 1),
            "total_stake": total_stake,
            "supporting_stake": supporting_stake,
            "consensus_ratio": supporting_stake / total_stake if total_stake else 0,
            "messages_processed": sum(
                n.stats.votes_cast + n.stats.measurements_made 
                for n in self.validators.values()
            ),
        }
    
    def _print_epoch_summary(self, epoch: int, stats: dict) -> None:
        """Print epoch summary"""
        self.log(f"\n--- Epoch {epoch} Summary ---")
        self.log(f"  Finalized: {stats['finalized']}")
        self.log(f"  Duration: {stats['duration_ms']:.1f}ms")
        self.log(f"  Consensus: {stats['consensus_ratio']*100:.1f}% stake")
        self.log(f"  Adversaries: {stats['adversaries_detected']}/{stats['adversaries']} detected")
        self.log(f"  False positives: {stats['false_positives']}")
    
    # =========================================================================
    # MULTI-EPOCH RUN
    # =========================================================================
    
    def run(self, num_epochs: int) -> dict:
        """Run multiple epochs and collect statistics"""
        self.log(f"\nRunning {num_epochs} epochs...")
        
        all_stats = []
        for epoch in range(num_epochs):
            stats = self.run_epoch(epoch)
            all_stats.append(stats)
        
        # Aggregate statistics
        return self._aggregate_stats(all_stats)
    
    def _aggregate_stats(self, all_stats: List[dict]) -> dict:
        """Aggregate statistics across epochs"""
        if not all_stats:
            return {}
        
        finalized_count = sum(1 for s in all_stats if s['finalized'])
        
        avg_duration = statistics.mean(s['duration_ms'] for s in all_stats)
        avg_consensus = statistics.mean(s['consensus_ratio'] for s in all_stats)
        
        # Sum across epochs
        total_adversaries = all_stats[0]['adversaries']  # Same each epoch
        total_honest = all_stats[0]['honest']
        total_detected = sum(s['adversaries_detected'] for s in all_stats)
        total_fp = sum(s['false_positives'] for s in all_stats)
        
        # Average detection across epochs
        avg_detection = statistics.mean(s['detection_rate'] for s in all_stats)
        avg_fp_rate = statistics.mean(s['false_positive_rate'] for s in all_stats)
        
        return {
            "epochs_run": len(all_stats),
            "epochs_finalized": finalized_count,
            "finalization_rate": finalized_count / len(all_stats),
            "avg_duration_ms": avg_duration,
            "avg_consensus_ratio": avg_consensus,
            "total_adversaries": total_adversaries,
            "total_honest": total_honest,
            "adversaries_detected_avg": total_detected / len(all_stats),
            "detection_rate": avg_detection,
            "false_positives_avg": total_fp / len(all_stats),
            "false_positive_rate": avg_fp_rate,
        }
    
    # =========================================================================
    # REPORTING
    # =========================================================================
    
    def get_network_status(self) -> dict:
        """Get current network status"""
        validator_states = defaultdict(int)
        for node in self.validators.values():
            validator_states[node.state.name] += 1
        
        zone_info = {}
        for zone_id, validator_ids in self.zones.items():
            zone_info[zone_id] = {
                "validators": len(validator_ids),
                "adversaries": sum(
                    1 for vid in validator_ids 
                    if self.validators[vid].config.is_adversary
                ),
            }
        
        return {
            "total_validators": len(self.validators),
            "zones": len(self.zones),
            "validator_states": dict(validator_states),
            "zone_info": zone_info,
            "finalized_blocks": len(self.finalized_blocks),
            "pending_messages": len(self.message_queue),
        }
    
    def print_final_report(self, results: dict) -> None:
        """Print final test report"""
        print("\n" + "=" * 70)
        print("QRTB TESTNET FINAL REPORT")
        print("=" * 70)
        
        print(f"\nNetwork Configuration:")
        print(f"  Zones: {self.config.num_zones}")
        print(f"  Validators per zone: {self.config.validators_per_zone}")
        print(f"  Total validators: {len(self.validators)}")
        print(f"  Adversary rate: {self.config.adversary_percentage*100:.0f}%")
        print(f"  Actual adversaries: {results.get('total_adversaries', 0)}")
        
        print(f"\nEpoch Results:")
        print(f"  Epochs run: {results['epochs_run']}")
        print(f"  Epochs finalized: {results['epochs_finalized']} ({results['finalization_rate']*100:.1f}%)")
        print(f"  Avg duration: {results['avg_duration_ms']:.1f}ms")
        print(f"  Avg consensus: {results['avg_consensus_ratio']*100:.1f}%")
        
        print(f"\nAdversary Detection:")
        print(f"  Adversaries per epoch: {results.get('total_adversaries', 0)}")
        print(f"  Avg detected per epoch: {results.get('adversaries_detected_avg', 0):.1f}")
        print(f"  Detection rate: {results['detection_rate']*100:.1f}%")
        print(f"  Avg false positives: {results.get('false_positives_avg', 0):.1f}")
        print(f"  False positive rate: {results['false_positive_rate']*100:.2f}%")
        
        print("\n" + "=" * 70)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_testnet(num_zones: int = 6, 
                  validators_per_zone: int = 5,
                  adversary_pct: float = 0.1) -> QRTBTestnet:
    """Create and initialize a testnet"""
    config = NetworkConfig(
        num_zones=num_zones,
        validators_per_zone=validators_per_zone,
        adversary_percentage=adversary_pct
    )
    
    testnet = QRTBTestnet(config)
    testnet.initialize_network()
    return testnet


def run_quick_test(num_epochs: int = 5) -> dict:
    """Run a quick testnet simulation"""
    testnet = create_testnet()
    results = testnet.run(num_epochs)
    testnet.print_final_report(results)
    return results
