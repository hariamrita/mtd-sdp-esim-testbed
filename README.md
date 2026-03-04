# mtd-sdp-esim-testbed

Experimental artifacts for the MTD-SDP-eSIM framework (ns-3, ONOS, Open5GS, P4).

START_README

# MTD-SDP-eSIM Experimental Testbed

This repository contains the experimental artifacts used in the evaluation of the **MTD-SDP-eSIM framework**, a hardware-anchored Zero Trust architecture integrating **Software-Defined Perimeter (SDP)**, **Software-Defined Networking (SDN)**, and **Moving Target Defense (MTD)** for secure eSIM provisioning in 6G IoT environments.

The testbed implements the architecture described in **Section 6.1 (Experimental Setup)** of the manuscript and enables reproducible evaluation of:

- Network Address Shuffling (NAS)
- ES-SPA authentication workflow
- ZTA policy enforcement
- eSIM Remote SIM Provisioning (RSP) flows
- Dynamic defense orchestration

---

# System Architecture

The testbed uses a **hybrid simulation–emulation architecture**.

| Component | Role |
|-----------|------|
| ns-3 (v3.42) | Simulates 6G RAN, UE mobility, and traffic generation |
| 6G-Library (ns-3 module) | Models sub-THz communication and 6G radio parameters |
| Open5GS (v2.7.1) | Emulates the 6G core network including SM-DP+ and SM-DS |
| ONOS (v2.7.0) | Implements the Zero Trust controller and policy engine |
| BMv2 P4 Switch | Data-plane enforcement of security policies |
| P4Runtime | Control-plane interface between ONOS and P4 switches |
| TAP/Bridge Interfaces | Connect simulated traffic to emulated network stack |

Architecture overview:

```
UEs (ns-3 simulation)
        |
      gNB
        |
  TAP / Bridge Interface
        |
   BMv2 P4 Switch
        |
     Open5GS Core
        |
     SM-DP+ / SM-DS
        |
   ONOS ZTA Controller
        |
     MTD NAS Module
```

---

# Repository Structure

```
MTD-SDP-eSIM/
│
├── ns3-simulation/
│   ├── ue-mobility.cc
│   ├── provisioning-scenario.cc
│   └── traffic-generator.cc
│
├── p4-programs/
│   ├── nas_switch.p4
│   └── pipeline.json
│
├── onos-controller/
│   ├── zta-policy-engine/
│   └── nas-trigger-module/
│
├── open5gs-config/
│   ├── smdp-config.yaml
│   └── subscriber-db.json
│
├── scripts/
│   ├── start-testbed.sh
│   ├── deploy-p4.sh
│   └── run-experiment.sh
│
└── results/
    ├── scalability/
    ├── dos-resilience/
    └── provisioning-latency/
```

---

# System Requirements

Tested on:

```
Ubuntu 22.04 LTS
Kernel >= 5.15
Docker >= 24.0
Python >= 3.10
```

Recommended hardware:

```
CPU: 8 cores
RAM: 16 GB
Storage: 50 GB
```

---

# Install Dependencies

## Install ns-3

```
sudo apt update
sudo apt install build-essential git cmake python3 python3-dev

git clone https://gitlab.com/nsnam/ns-3-dev.git
cd ns-3-dev
git checkout ns-3.42
./ns3 configure
./ns3 build
```

Install the **6G-Library module**:

```
cd contrib
git clone https://github.com/<your-repo>/ns3-6g-library.git
```

Rebuild:

```
./ns3 build
```

---

## Install Open5GS

```
sudo apt install open5gs
```

Start services:

```
sudo systemctl start open5gs-amfd
sudo systemctl start open5gs-smfd
sudo systemctl start open5gs-upfd
```

---

## Install BMv2 and P4

```
sudo apt install p4lang-bmv2 p4lang-p4c
```

Compile P4 program:

```
cd p4-programs
p4c --target bmv2 --arch v1model nas_switch.p4
```

Run switch:

```
simple_switch_grpc pipeline.json
```

---

## Install ONOS Controller

```
git clone https://gerrit.onosproject.org/onos
cd onos
git checkout onos-2.7
bazel build onos
```

Start ONOS:

```
bazel run onos-local
```

---

# Running the Testbed

### Step 1 Start Core Network

```
sudo systemctl start open5gs
```

### Step 2 Launch P4 Switch

```
./scripts/deploy-p4.sh
```

### Step 3 Start ONOS Controller

```
onos-service start
```

### Step 4 Start ns-3 Simulation

```
cd ns3-simulation
./ns3 run provisioning-scenario
```

### Step 5 Trigger NAS Events

```
python scripts/run-experiment.sh
```

---

# Reproducing Experiments

| Experiment | Script |
|------------|-------|
| DoS Resilience | scripts/run-dos-test.sh |
| Provisioning Scalability | scripts/run-scale-test.sh |
| NAS Effectiveness | scripts/run-nas-eval.sh |
| Energy Overhead | scripts/run-energy-test.sh |

Results are stored in:

```
results/
```

---

# Key Parameters

| Parameter | Value |
|-----------|------|
| Fleet size | 100–1000 devices |
| NAS shuffle interval | adaptive |
| Threat threshold θ | 0.5 |
| Shuffle effectiveness ε | 0.15 |
| Experimental runs | 30 |

---

# Citation

```
@article{MTD-SDP-eSIM,
title = {Hardware-Anchored Zero Trust Architecture for Secure eSIM Provisioning in 6G IoT Networks},
journal = {Future Internet},
year = {2026}
}
```

---

# License

MIT License

---

# Contact

For artifact issues:

```
your-email@domain.com
```

END_README
