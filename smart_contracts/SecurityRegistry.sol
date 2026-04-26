// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title SecurityRegistry
 * @dev Immutable log of security events and RFID authorizations
 */
contract SecurityRegistry {

    struct SecurityEvent {
        string  deviceId;
        string  eventType;
        string  dataHash;
        uint256 timestamp;
        address submitter;
    }

    struct RfidToken {
        string  uid;
        string  owner;
        bool    active;
        uint256 registeredAt;
    }

    mapping(uint256 => SecurityEvent) public events;
    mapping(string  => RfidToken)     public rfidTokens;
    uint256 public eventCount;

    event EventLogged(uint256 indexed id, string deviceId, string eventType, uint256 timestamp);
    event RfidRegistered(string uid, string owner);
    event EmergencyRevoke(string uid, address revokedBy);

    function logEvent(
        string memory deviceId,
        string memory eventType,
        string memory dataHash,
        uint256 timestamp
    ) public returns (uint256) {
        eventCount++;
        events[eventCount] = SecurityEvent(deviceId, eventType, dataHash, timestamp, msg.sender);
        emit EventLogged(eventCount, deviceId, eventType, timestamp);
        return eventCount;
    }

    function registerRfid(string memory uid, string memory owner) public {
        rfidTokens[uid] = RfidToken(uid, owner, true, block.timestamp);
        emit RfidRegistered(uid, owner);
    }

    function isRfidRegistered(string memory uid) public view returns (bool) {
        return rfidTokens[uid].active;
    }

    function emergencyRevoke(string memory uid) public {
        rfidTokens[uid].active = false;
        emit EmergencyRevoke(uid, msg.sender);
    }

    function getEvent(uint256 id) public view returns (
        string memory deviceId, string memory eventType,
        string memory dataHash, uint256 timestamp, address submitter
    ) {
        SecurityEvent memory e = events[id];
        return (e.deviceId, e.eventType, e.dataHash, e.timestamp, e.submitter);
    }
}
