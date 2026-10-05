// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @notice Commitments and attributed decisions, never an oracle of scanner truth.
/// No proxy, funds, arbitrary calls, or modification of historical commitments.
contract EvidenceNotary is AccessControlDefaultAdminRules, EIP712 {
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant REVIEWER_ROLE = keccak256("REVIEWER_ROLE");
    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");
    bytes32 public constant SUPPLIER_ROLE = keccak256("SUPPLIER_ROLE");
    bytes32 public constant DECISION_TYPEHASH = keccak256("Decision(bytes32 proposalId,uint256 version,bytes32 proposalDigest,bool approve,address reviewer,uint256 nonce,uint256 deadline)");

    enum State { Absent, Proposed, Approved, Rejected, Cancelled, ResultRecorded }
    struct Proposal {
        bytes32 digest;
        address proposer;
        address reviewer;
        uint64 expiresAt;
        State state;
        bytes32 resultRoot;
        bytes32 resultDigest;
        address verifier;
    }
    struct Attestation {
        bytes32 digest;
        address supplier;
        uint64 validUntil;
        bytes32 predecessor;
        bytes32 supersededBy;
        bool revoked;
    }
    mapping(bytes32 => mapping(uint256 => Proposal)) public proposals;
    mapping(bytes32 => uint256) public latestVersion;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => Attestation) public attestations;

    error InvalidRecord();
    error InvalidState();
    error Expired();
    error WrongVersion();
    error SeparationOfDuties();
    error InvalidNonce();
    error InvalidSigner();
    event ProposalRecorded(bytes32 indexed id, uint256 indexed version, bytes32 digest, address proposer, uint64 expiresAt);
    event DecisionRecorded(bytes32 indexed id, uint256 indexed version, bytes32 digest, address reviewer, bool approved, uint256 nonce);
    event ProposalCancelled(bytes32 indexed id, uint256 indexed version, address actor);
    event ResultRecorded(bytes32 indexed id, uint256 indexed version, bytes32 resultRoot, bytes32 resultDigest, address verifier);
    event SupplierAttested(bytes32 indexed id, bytes32 indexed predecessor, bytes32 digest, address supplier, uint64 validUntil);
    event SupplierRevoked(bytes32 indexed id, bytes32 reasonDigest, address actor);

    constructor(address admin) AccessControlDefaultAdminRules(1 days, admin) EIP712("ECDAT EvidenceNotary", "1") {}

    function propose(bytes32 id, uint256 version, bytes32 digest, uint64 expiresAt) external onlyRole(PROPOSER_ROLE) {
        if (id == bytes32(0) || digest == bytes32(0)) revert InvalidRecord();
        if (expiresAt <= block.timestamp) revert Expired();
        uint256 previous = latestVersion[id];
        if (version != previous + 1) revert WrongVersion();
        if (previous != 0) {
            Proposal storage old = proposals[id][previous];
            if (old.proposer != msg.sender) revert InvalidSigner();
            if (old.state == State.Approved || old.state == State.ResultRecorded) revert InvalidState();
        }
        latestVersion[id] = version;
        proposals[id][version] = Proposal(digest, msg.sender, address(0), expiresAt, State.Proposed, bytes32(0), bytes32(0), address(0));
        emit ProposalRecorded(id, version, digest, msg.sender, expiresAt);
    }

    /// @notice Anyone may relay a signed decision, but cannot change its identity or scope.
    function decide(bytes32 id, uint256 version, bytes32 digest, bool approve, address reviewer, uint256 nonce, uint256 deadline, bytes calldata signature) external {
        if (latestVersion[id] != version) revert WrongVersion();
        Proposal storage p = proposals[id][version];
        if (p.state != State.Proposed || p.digest != digest) revert InvalidState();
        if (block.timestamp > deadline || block.timestamp >= p.expiresAt) revert Expired();
        _checkRole(REVIEWER_ROLE, reviewer);
        if (p.proposer == reviewer) revert SeparationOfDuties();
        if (nonces[reviewer] != nonce) revert InvalidNonce();
        bytes32 payload = keccak256(abi.encode(DECISION_TYPEHASH, id, version, digest, approve, reviewer, nonce, deadline));
        if (ECDSA.recover(_hashTypedDataV4(payload), signature) != reviewer) revert InvalidSigner();
        nonces[reviewer] = nonce + 1;
        p.reviewer = reviewer;
        p.state = approve ? State.Approved : State.Rejected;
        emit DecisionRecorded(id, version, digest, reviewer, approve, nonce);
    }

    function cancel(bytes32 id, uint256 version) external {
        Proposal storage p = proposals[id][version];
        if (latestVersion[id] != version) revert WrongVersion();
        if (p.state != State.Proposed && p.state != State.Approved) revert InvalidState();
        if (msg.sender != p.proposer && msg.sender != p.reviewer) revert InvalidSigner();
        p.state = State.Cancelled;
        emit ProposalCancelled(id, version, msg.sender);
    }

    function recordResult(bytes32 id, uint256 version, bytes32 root, bytes32 resultDigest) external onlyRole(VERIFIER_ROLE) {
        if (latestVersion[id] != version) revert WrongVersion();
        Proposal storage p = proposals[id][version];
        if (p.state != State.Approved) revert InvalidState();
        if (block.timestamp >= p.expiresAt) revert Expired();
        if (msg.sender == p.proposer || msg.sender == p.reviewer) revert SeparationOfDuties();
        if (root == bytes32(0) || resultDigest == bytes32(0)) revert InvalidRecord();
        p.resultRoot = root;
        p.resultDigest = resultDigest;
        p.verifier = msg.sender;
        p.state = State.ResultRecorded;
        emit ResultRecorded(id, version, root, resultDigest, msg.sender);
    }

    function attest(bytes32 id, bytes32 digest, uint64 validUntil, bytes32 predecessor) external onlyRole(SUPPLIER_ROLE) {
        if (id == bytes32(0) || digest == bytes32(0) || attestations[id].supplier != address(0)) revert InvalidRecord();
        if (validUntil <= block.timestamp) revert Expired();
        if (predecessor != bytes32(0)) {
            Attestation storage old = attestations[predecessor];
            if (old.supplier != msg.sender) revert InvalidSigner();
            if (old.supersededBy != bytes32(0)) revert InvalidState();
            old.supersededBy = id;
        }
        attestations[id] = Attestation(digest, msg.sender, validUntil, predecessor, bytes32(0), false);
        emit SupplierAttested(id, predecessor, digest, msg.sender, validUntil);
    }

    function revokeAttestation(bytes32 id, bytes32 reasonDigest) external {
        Attestation storage a = attestations[id];
        if (a.supplier != msg.sender || a.supplier == address(0)) revert InvalidSigner();
        if (a.revoked || reasonDigest == bytes32(0)) revert InvalidState();
        a.revoked = true;
        emit SupplierRevoked(id, reasonDigest, msg.sender);
    }
}
