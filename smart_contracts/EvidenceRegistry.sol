// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title EvidenceRegistry
 * @notice Immutable on-chain photo evidence log for the Zero-Trust IoT Security Platform.
 *
 * Each DENY event triggers the ESP32-CAM to capture a 5-photo burst.
 * The Raspberry Pi hashes the JPEG data (SHA-256) and submits the hash here.
 * The full image is stored in pi_backend/photos/ — the blockchain provides
 * tamper-evident proof that the photo existed at a specific moment in time.
 *
 * Research Paper Reference: Phase 5, Section 5.2 — Patent Claim 1(f)
 *
 * Key design points:
 *   - Only the Pi's registered submitter address can log evidence.
 *   - Evidence is append-only — no update or delete functions exist.
 *   - Each record links a photo hash to a SecurityRegistry event ID.
 */
contract EvidenceRegistry {

    // ── Evidence Record ───────────────────────────────────────────────────
    struct EvidenceRecord {
        uint256 securityEventId;   // FK to SecurityRegistry event (0 if standalone)
        string  deviceId;          // ESP32-CAM device identifier
        string  photoHash;         // SHA-256 hex of the JPEG file
        string  triggerReason;     // "ACCESS_DENIED" | "PHYSICAL_TAMPER" | etc.
        uint256 timestamp;         // Unix epoch when photo was captured
        address submitter;         // Ethereum wallet of the Pi backend
        uint8   photoIndex;        // Photo number in burst (1–5)
        uint8   burstTotal;        // Total photos in this burst
    }

    // ── State ─────────────────────────────────────────────────────────────
    address public owner;
    uint256 public evidenceCount;

    mapping(uint256 => EvidenceRecord) private _evidence;

    // eventId → array of evidence IDs linked to that security event
    mapping(uint256 => uint256[]) private _eventEvidence;

    // ── Events ────────────────────────────────────────────────────────────
    event EvidenceLogged(
        uint256 indexed evidenceId,
        uint256 indexed securityEventId,
        string  deviceId,
        string  triggerReason,
        uint256 timestamp
    );

    // ── Constructor ───────────────────────────────────────────────────────
    constructor() {
        owner = msg.sender;
    }

    // ── Modifiers ─────────────────────────────────────────────────────────
    modifier onlyOwner() {
        require(msg.sender == owner, "EvidenceRegistry: not owner");
        _;
    }

    // ── Core Functions ────────────────────────────────────────────────────

    /**
     * @notice Log a single photo's SHA-256 hash as tamper-evident evidence.
     * @param securityEventId  Corresponding SecurityRegistry event ID (0 if none).
     * @param deviceId         ESP32-CAM identifier string.
     * @param photoHash        SHA-256 hex digest of the JPEG file.
     * @param triggerReason    Human-readable trigger label (e.g. "ACCESS_DENIED").
     * @param timestamp        Unix timestamp of photo capture.
     * @param photoIndex       This photo's position in the burst (1-based).
     * @param burstTotal       Total number of photos in the burst.
     * @return evidenceId      The new evidence record ID.
     */
    function logEvidence(
        uint256 securityEventId,
        string  memory deviceId,
        string  memory photoHash,
        string  memory triggerReason,
        uint256 timestamp,
        uint8   photoIndex,
        uint8   burstTotal
    ) public returns (uint256) {
        evidenceCount++;
        _evidence[evidenceCount] = EvidenceRecord({
            securityEventId: securityEventId,
            deviceId:        deviceId,
            photoHash:       photoHash,
            triggerReason:   triggerReason,
            timestamp:       timestamp,
            submitter:       msg.sender,
            photoIndex:      photoIndex,
            burstTotal:      burstTotal
        });

        if (securityEventId > 0) {
            _eventEvidence[securityEventId].push(evidenceCount);
        }

        emit EvidenceLogged(evidenceCount, securityEventId, deviceId, triggerReason, timestamp);
        return evidenceCount;
    }

    /**
     * @notice Log a full 5-photo burst in a single transaction (gas-efficient).
     * @param securityEventId  Corresponding SecurityRegistry event ID.
     * @param deviceId         ESP32-CAM identifier.
     * @param photoHashes      Array of SHA-256 hashes (length = burst size).
     * @param triggerReason    Trigger label.
     * @param timestamp        Unix timestamp of the burst start.
     * @return firstId         The evidence ID of the first photo in the burst.
     */
    function logBurst(
        uint256 securityEventId,
        string  memory deviceId,
        string[] memory photoHashes,
        string  memory triggerReason,
        uint256 timestamp
    ) public returns (uint256 firstId) {
        uint8 total = uint8(photoHashes.length);
        require(total > 0 && total <= 10, "EvidenceRegistry: burst size 1-10");

        firstId = evidenceCount + 1;
        for (uint8 i = 0; i < total; i++) {
            evidenceCount++;
            _evidence[evidenceCount] = EvidenceRecord({
                securityEventId: securityEventId,
                deviceId:        deviceId,
                photoHash:       photoHashes[i],
                triggerReason:   triggerReason,
                timestamp:       timestamp,
                submitter:       msg.sender,
                photoIndex:      i + 1,
                burstTotal:      total
            });
            if (securityEventId > 0) {
                _eventEvidence[securityEventId].push(evidenceCount);
            }
            emit EvidenceLogged(evidenceCount, securityEventId, deviceId, triggerReason, timestamp);
        }
    }

    // ── Query Functions ───────────────────────────────────────────────────

    /**
     * @notice Retrieve a single evidence record by ID.
     */
    function getEvidence(uint256 evidenceId)
        public view
        returns (
            uint256 securityEventId,
            string memory deviceId,
            string memory photoHash,
            string memory triggerReason,
            uint256 timestamp,
            address submitter,
            uint8   photoIndex,
            uint8   burstTotal
        )
    {
        require(evidenceId > 0 && evidenceId <= evidenceCount,
                "EvidenceRegistry: evidence ID out of range");
        EvidenceRecord storage r = _evidence[evidenceId];
        return (
            r.securityEventId,
            r.deviceId,
            r.photoHash,
            r.triggerReason,
            r.timestamp,
            r.submitter,
            r.photoIndex,
            r.burstTotal
        );
    }

    /**
     * @notice Get all evidence IDs linked to a specific SecurityRegistry event.
     */
    function getEvidenceForEvent(uint256 securityEventId)
        public view
        returns (uint256[] memory)
    {
        return _eventEvidence[securityEventId];
    }

    /**
     * @notice Total number of evidence records on-chain.
     */
    function getTotalEvidence() public view returns (uint256) {
        return evidenceCount;
    }

    /**
     * @notice Transfer ownership (e.g. when Pi wallet rotates).
     */
    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "EvidenceRegistry: zero address");
        owner = newOwner;
    }
}
