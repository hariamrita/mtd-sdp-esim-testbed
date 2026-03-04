# mtd-sdp-esim-testbed

Experimental artifacts for the MTD-SDP-eSIM framework (ns-3, ONOS, Open5GS, P4).



MTD-SDP-eSIM Experimental Testbed



This repository contains the experimental artifacts used in the evaluation of the MTD-SDP-eSIM framework, a hardware-anchored Zero Trust architecture integrating Software-Defined Perimeter (SDP), Software-Defined Networking (SDN), and Moving Target Defense (MTD) for secure eSIM provisioning in 6G IoT environments.



The testbed implements the architecture described in Section 6.1 (Experimental Setup) of the manuscript and enables reproducible evaluation of:



Network Address Shuffling (NAS)



ES-SPA authentication workflow



ZTA policy enforcement



eSIM Remote SIM Provisioning (RSP) flows



Dynamic defense orchestration



System Architecture



The testbed uses a hybrid simulation–emulation architecture.



| Component                    | Role                                                    |

| ---------------------------- | ------------------------------------------------------- |

| \*\*ns-3 (v3.42)\*\*             | Simulates 6G RAN, UE mobility, and traffic generation   |

| \*\*6G-Library (ns-3 module)\*\* | Models sub-THz communication and 6G radio parameters    |

| \*\*Open5GS (v2.7.1)\*\*         | Emulates the 6G core network including SM-DP+ and SM-DS |

| \*\*ONOS (v2.7.0)\*\*            | Implements the Zero Trust controller and policy engine  |

| \*\*BMv2 P4 Switch\*\*           | Data-plane enforcement of security policies             |

| \*\*P4Runtime\*\*                | Control-plane interface between ONOS and P4 switches    |

| \*\*TAP/Bridge Interfaces\*\*    | Connect simulated traffic to emulated network stack     |





Architecture overview:



UEs (ns-3 simulation)

&nbsp;       |

&nbsp;     gNB

&nbsp;       |

&nbsp; TAP / Bridge Interface

&nbsp;       |

&nbsp;  BMv2 P4 Switch

&nbsp;       |

&nbsp;    Open5GS Core

&nbsp;       |

&nbsp;    SM-DP+ / SM-DS

&nbsp;       |

&nbsp;  ONOS ZTA Controller

&nbsp;       |

&nbsp;    MTD NAS Module





Repository Structure



MTD-SDP-eSIM/

│

├── ns3-simulation/

│   ├── ue-mobility.cc

│   ├── provisioning-scenario.cc

│   └── traffic-generator.cc

│

├── p4-programs/

│   ├── nas\_switch.p4

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

&nbsp;   ├── scalability/

&nbsp;   ├── dos-resilience/

&nbsp;   └── provisioning-latency/



System Requirements



Tested on:



Ubuntu 22.04 LTS

Kernel >= 5.15

Docker >= 24.0

Python >= 3.10



Hardware recommended:



CPU: 8 cores

RAM: 16 GB

Storage: 50 GB



Install Dependencies

1 Install ns-3



sudo apt update

sudo apt install build-essential git cmake python3 python3-dev



git clone https://gitlab.com/nsnam/ns-3-dev.git

cd ns-3-dev

git checkout ns-3.42

./ns3 configure

./ns3 build



Install the 6G-Library module:

























