# Zero-Trust-IoT-Framework
Zero-trust IoT framework with LSTM-based behavioral fingerprinting, Solidity smart contracts, and edge tamper detection.
# Zero-Trust IoT Framework

A budget-friendly, patentable zero-trust IoT security system developed by VIT Pune students **Mridul Pandey** and **Onkar**.

This project implements a **tri-modal security framework** combining:
- 🧠 **LSTM-based ML fingerprinting** for behavioral device identity
- 🔗 **Blockchain smart contracts** for dynamic access control
- ⚡ **Physical tamper detection** via edge sensors

---

## 📘 Overview
The framework integrates machine learning, blockchain, and hardware security to address cyber-physical threats in IoT systems. It emphasizes **behavioral authentication** over static identity, enabling resilient, low-cost, and patentable IoT security.

---

## 🔑 Core Components
- **ML Model**:  
  - LSTM neural network trained on features like RSSI, packet size, CPU temp, heap, inter-packet delay  
  - Achieves **94.2% accuracy**  
  - Converted to **TensorFlow Lite** for Raspberry Pi edge inference (~50–200ms latency)

- **Blockchain**:  
  - Solidity smart contract (`DeviceRegistry.sol`) with dynamic thresholds, re-verification, and emergency revocation  
  - Deployed via **Hardhat** to **Ganache/Arbitrum testnet**

- **Hardware/Edge**:  
  - Raspberry Pi 5 (Pironman 5)  
  - ESP32 devices sending telemetry via Flask API  
  - SQLite storage, GPIO vibration sensor (SW-420)  
  - Optional Coral TPU/TPM acceleration

---

## 🗓 Implementation Plan
| Phase | Focus                  | Deliverables                     | Timeline   |
|-------|------------------------|----------------------------------|------------|
| 1–2   | Setup & Blockchain     | Devices connected, contract live | Weeks 1–2  |
| 3–4   | ML & Data              | 500+ samples, trained LSTM       | Weeks 3–4  |
| 5–7   | Integration & Hardening| End-to-end system, tamper detect | Weeks 5–7  |
| 8–10  | Testing & Optimization | Audits, 10-device load, 200ms    | Weeks 8–10 |
| 11–12 | Docs & Patent          | Reports, claims, filing          | Weeks 11–12|

---

## 💰 Budget & Novelty
- Hardware cost: ~₹950 (ESP32s, sensors)  
- Software: Free/open-source  
- Novelty: Tri-factor authentication, neural fingerprints, kinetic lockdown  
- Patent strategy: USPTO provisional (~$150)

---

## 📊 Success Metrics
- Target accuracy: **≥95%**  
- Latency: **<500ms** end-to-end  
- Scalability: **10+ devices** under load

---

## 📂 Repository Structure (planned)
