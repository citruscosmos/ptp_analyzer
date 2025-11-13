# PTP Network Analyzer

## 1. Overview

This is a Python-based command-line tool for real-time monitoring and analysis of Precision Time Protocol (PTP) v2 (IEEE 1588-2008) network traffic.

The script captures PTP messages on a specified network interface to provide a clear, real-time view of the network's PTP status, including the current Grandmaster (GM), all potential master clocks, detected slave devices, and time synchronization details.

## 2. Features

- **Real-time PTP Message Analysis**: Captures and analyzes Announce, Sync, Follow_Up, Delay_Req, and Delay_Resp messages.
- **Grandmaster Identification**: Automatically identifies the current Grandmaster clock based on the Best Master Clock Algorithm (BMCA).
- **Detailed BMCA Information**: Displays a list of all potential master clocks detected on the network, along with their BMCA parameters (Priorities, Clock Class, Accuracy, etc.), making it easy to understand why the current GM was chosen.
- **GM Change History**: Tracks and displays the previous Grandmaster after a changeover event, which helps in diagnosing network stability issues.
- **Slave Node Detection**: Identifies and lists all slave nodes that are sending `Delay_Req` messages.
- **Time and Leap Second Monitoring**: Shows the current PTP time (TAI), the TAI-UTC offset, and any pending leap second announcements.
- **Multi-threaded Design**: Uses a background thread for packet capture, ensuring the user interface remains responsive.

## 3. Requirements

- **Language**: Python 3.x
- **Library**: `scapy`
- **Permissions**: Root or Administrator privileges are required to capture raw network packets.

## 4. Installation

1.  **Clone the repository or download the script.**

2.  **Install the required dependencies:**
    Navigate to the project directory and run:
    ```bash
    pip install -r requirements.txt
    ```

## 5. Usage

Run the script from the command line, specifying the network interface you wish to monitor using the `-i` or `--interface` argument.

**Syntax:**
```bash
sudo python3 ptp_analyzer.py -i <interface_name>
```

**Example:**
```bash
sudo python3 ptp_analyzer.py -i eth0
```

Press `Ctrl+C` to stop the monitor.

## 6. Example Output

```
================ PTP Network Monitor ================
Interface: eth0

--- Grandmaster (GM) ---
  GM Clock Identity: 0x001122aabbccdeff
  Priority 1 / 2:    128 / 128
  Clock Class:       6
  Clock Accuracy:    33
  Clock Variance:    -4000

--- Previous Grandmaster ---
  GM Clock Identity: 0x001122aabbcc1122
  Priority 1 / 2:    128 / 128

--- All Potential Masters (from Announce Msgs) ---
- 0x001122aabbcc1122 | P1:128 P2:128 | Class:6 Acc:33 Var:-4000
- 0x001122aabbccdeff | P1:128 P2:128 | Class:6 Acc:33 Var:-4000 (Current GM)

--- Time & Leap Second ---
  Current PTP Time (TAI): 2024-10-28 14:30:55.123
  UTC Offset (TAI-UTC):   37 s
  UTC Offset Valid:       True
  Leap Second Pending:    None

--- Detected Slaves (Sending Delay_Req) ---
- 0x9988776655443322
- 0xaabbccddeeff0011

===================================================
```
