#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PTP Network Analyzer
This script captures and analyzes PTP (IEEE 1588-2008) messages on a network interface
to monitor the current grandmaster, slave nodes, PTP time, and leap second information.
"""

import argparse
import os
import sys
import time
from datetime import datetime
from threading import Lock, Thread

from scapy.all import *

# Load PTP extension for Scapy
load_contrib("ptp")
PTPv2 = PTP

# --- Constants ---
PTP_EVENT_PORT = 319
PTP_GENERAL_PORT = 320
_SYNC = 0
_DELAY_REQ = 1
_FOLLOW_UP = 8
_ANNOUNCE = 11
POTENTIAL_GM_TIMEOUT = 30  # Seconds to wait for an Announce msg before removing a potential GM

# --- Global variables to store network state ---
ptp_data = {
    "grandmaster": None,
    "previous_grandmaster": None,
    "potential_gms": {},
    "slaves": set(),
    "last_ptp_time": None,
    "utc_offset": None,
    "utc_offset_valid": False,
    "leap_61": False,
    "leap_59": False,
}
data_lock = Lock()


def ptp_timestamp_to_datetime(seconds: int, nanoseconds: int) -> datetime:
    """
    Converts a PTP timestamp (seconds + nanoseconds) to a Python datetime object.

    Args:
        seconds (int): The seconds part of the PTP timestamp.
        nanoseconds (int): The nanoseconds part of the PTP timestamp.

    Returns:
        datetime: The converted datetime object, or None if input is invalid.
    """
    if seconds is None or nanoseconds is None:
        return None
    return datetime.fromtimestamp(seconds + nanoseconds / 1e9)


def update_grandmaster():
    """
    Selects the best Grandmaster from the list of potential GMs based on the
    Best Master Clock Algorithm (BMCA). It also removes stale potential GMs
    that have not sent an Announce message recently.
    """
    with data_lock:
        # Remove stale potential GMs
        current_time = time.time()
        stale_gms = [
            gm_id
            for gm_id, gm_data in ptp_data["potential_gms"].items()
            if current_time - gm_data["last_seen"] > POTENTIAL_GM_TIMEOUT
        ]
        for gm_id in stale_gms:
            del ptp_data["potential_gms"][gm_id]

        if not ptp_data["potential_gms"]:
            ptp_data["grandmaster"] = None
            return

        # Sort potential GMs based on BMCA criteria
        best_gm = sorted(
            ptp_data["potential_gms"].values(),
            key=lambda gm: (
                gm["priority1"],
                gm["clockQuality"]["clockClass"],
                gm["clockQuality"]["clockAccuracy"],
                gm["clockQuality"]["offsetScaledLogVariance"],
                gm["priority2"],
                gm["clockIdentity"],
            ),
        )[0]

        # If GM changes, store the old one for historical view
        current_gm = ptp_data.get("grandmaster")
        if current_gm and current_gm["clockIdentity"] != best_gm["clockIdentity"]:
            ptp_data["previous_grandmaster"] = current_gm
        elif not current_gm and best_gm:
             # Set initial GM without setting previous_gm
             pass

        ptp_data["grandmaster"] = best_gm


def packet_callback(packet: Packet):
    """
    Callback function to process each captured packet.
    It filters for PTPv2 messages and updates the global state.

    Args:
        packet (Packet): The captured packet from Scapy.
    """
    if not packet.haslayer(PTPv2) or packet[PTPv2].versionPTP != 2:
        return

    ptp_msg = packet[PTPv2]
    msg_type = ptp_msg.messageType

    with data_lock:
        # Announce Message: Update potential GMs and UTC/leap info
        if msg_type == _ANNOUNCE:
            gm_identity = ptp_msg.grandmasterIdentity
            ptp_data["potential_gms"][gm_identity] = {
                "clockIdentity": gm_identity,
                "priority1": ptp_msg.grandmasterPriority1,
                "priority2": ptp_msg.grandmasterPriority2,
                "clockQuality": {
                    "clockClass": ptp_msg.grandmasterClockQuality.clockClass,
                    "clockAccuracy": ptp_msg.grandmasterClockQuality.clockAccuracy,
                    "offsetScaledLogVariance": ptp_msg.grandmasterClockQuality.offsetScaledLogVariance,
                },
                "last_seen": time.time(),
            }
            # Update UTC offset and leap second flags only from the current GM
            if ptp_data["grandmaster"] and ptp_data["grandmaster"]["clockIdentity"] == gm_identity:
                ptp_data["utc_offset"] = ptp_msg.currentUtcOffset
                flags = ptp_msg.flags
                ptp_data["leap_61"] = bool(flags & 0b00000001)  # LEAP61
                ptp_data["leap_59"] = bool(flags & 0b00000010)  # LEAP59
                ptp_data["utc_offset_valid"] = bool(flags & 0b00000100)  # UTC_OFFSET_VALID

        # Delay_Req Message: Detect slave nodes
        elif msg_type == _DELAY_REQ:
            slave_id = ptp_msg.header.sourceClockIdentity
            ptp_data["slaves"].add(f"0x{slave_id:016x}")

        # Sync/Follow_Up Message: Update PTP time
        elif msg_type in (_SYNC, _FOLLOW_UP):
            source_id = ptp_msg.header.sourceClockIdentity
            if ptp_data["grandmaster"] and source_id == ptp_data["grandmaster"]["clockIdentity"]:
                timestamp = None
                if msg_type == _FOLLOW_UP and hasattr(ptp_msg, 'preciseOriginTimestamp'):
                    timestamp = ptp_timestamp_to_datetime(
                        ptp_msg.preciseOriginTimestamp.seconds,
                        ptp_msg.preciseOriginTimestamp.nanoseconds,
                    )
                elif msg_type == _SYNC:
                    # Use Sync as a fallback if no Follow_Up is received
                    timestamp = ptp_timestamp_to_datetime(
                        ptp_msg.originTimestamp.seconds, ptp_msg.originTimestamp.nanoseconds
                    )

                if timestamp:
                    ptp_data["last_ptp_time"] = timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    # Trigger a grandmaster update after processing an Announce message
    if msg_type == _ANNOUNCE:
        update_grandmaster()


def display_status(interface_name: str):
    """
    Clears the console and displays the current PTP network status,
    including details of the current and previous GM, and all potential masters.

    Args:
        interface_name (str): The name of the network interface being monitored.
    """
    os.system("cls" if os.name == "nt" else "clear")
    print("================ PTP Network Monitor ================")
    print(f"Interface: {interface_name}\n")

    with data_lock:
        # --- Display Current Grandmaster ---
        gm = ptp_data.get("grandmaster")
        print("--- Grandmaster (GM) ---")
        if gm:
            print(f"  GM Clock Identity: 0x{gm['clockIdentity']:016x}")
            print(f"  Priority 1 / 2:    {gm['priority1']} / {gm['priority2']}")
            print(f"  Clock Class:       {gm['clockQuality']['clockClass']}")
            print(f"  Clock Accuracy:    {gm['clockQuality']['clockAccuracy']}")
            print(f"  Clock Variance:    {gm['clockQuality']['offsetScaledLogVariance']}\n")
        else:
            print("  Searching...\n")

        # --- Display Previous Grandmaster ---
        prev_gm = ptp_data.get("previous_grandmaster")
        if prev_gm:
            print("--- Previous Grandmaster ---")
            print(f"  GM Clock Identity: 0x{prev_gm['clockIdentity']:016x}")
            print(f"  Priority 1 / 2:    {prev_gm['priority1']} / {prev_gm['priority2']}\n")


        # --- Display All Potential Masters ---
        potential_gms = ptp_data["potential_gms"].values()
        print("--- All Potential Masters (from Announce Msgs) ---")
        if potential_gms:
            # Sort for consistent display
            sorted_gms = sorted(potential_gms, key=lambda x: x['clockIdentity'])
            for p_gm in sorted_gms:
                is_current_gm = " (Current GM)" if gm and p_gm['clockIdentity'] == gm['clockIdentity'] else ""
                print(
                    f"- 0x{p_gm['clockIdentity']:016x} | "
                    f"P1:{p_gm['priority1']} P2:{p_gm['priority2']} | "
                    f"Class:{p_gm['clockQuality']['clockClass']} "
                    f"Acc:{p_gm['clockQuality']['clockAccuracy']} "
                    f"Var:{p_gm['clockQuality']['offsetScaledLogVariance']}{is_current_gm}"
                )
        else:
            print("  None detected.")
        print("")


        # --- Display Time & Leap Second Info ---
        print("--- Time & Leap Second ---")
        ptp_time = ptp_data.get("last_ptp_time") or "Waiting for GM..."
        utc_offset = ptp_data.get("utc_offset")
        utc_valid = ptp_data.get("utc_offset_valid", False)
        leap_pending = "None"
        if ptp_data.get("leap_61"):
            leap_pending = "ADD"
        elif ptp_data.get("leap_59"):
            leap_pending = "SUB"

        print(f"  Current PTP Time (TAI): {ptp_time}")
        print(f"  UTC Offset (TAI-UTC):   {utc_offset} s" if utc_offset is not None else "  UTC Offset (TAI-UTC):   N/A")
        print(f"  UTC Offset Valid:       {utc_valid}")
        print(f"  Leap Second Pending:    {leap_pending}\n")

        # --- Display Detected Slaves ---
        slaves = ptp_data["slaves"]
        print("--- Detected Slaves (Sending Delay_Req) ---")
        if slaves:
            for slave in sorted(list(slaves)):
                print(f"- {slave}")
        else:
            print("  None detected.")
    print("\n===================================================")


def main():
    """
    Main function to start the PTP network analyzer.
    Parses command-line arguments, checks for root privileges,
    and starts the packet sniffing and display threads.
    """
    parser = argparse.ArgumentParser(
        description="PTP Network Analyzer - Monitors PTPv2 network traffic."
    )
    parser.add_argument(
        "-i", "--interface", required=True, help="Network interface to monitor (e.g., eth0)"
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Error: This script must be run as root to capture network packets.", file=sys.stderr)
        sys.exit(1)

    print(f"Starting PTP monitor on interface {args.interface}...")
    print("Press Ctrl+C to stop.")

    # Start packet sniffing in a background thread
    sniffer_thread = Thread(
        target=sniff,
        kwargs={
            "iface": args.interface,
            "prn": packet_callback,
            "filter": f"udp port {PTP_EVENT_PORT} or udp port {PTP_GENERAL_PORT}",
            "store": 0,
        },
        daemon=True,
    )
    sniffer_thread.start()

    try:
        while True:
            display_status(args.interface)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nStopping PTP monitor.")
        sys.exit(0)


if __name__ == "__main__":
    main()
