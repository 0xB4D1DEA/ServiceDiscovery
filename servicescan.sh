#!/usr/bin/env bash
set -euo pipefail
# Start logging everything to scan_output.log
exec > >(tee scan_output.log) 2>&1

# -------------------------------------------------------------
# Usage check
# -------------------------------------------------------------
if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <targets.txt>"
  exit 1
fi
TARGETS=$1
if [[ ! -f $TARGETS ]]; then
  echo "ERROR: '$TARGETS' not found."
  exit 1
fi

# -------------------------------------------------------------
# Filenames & parameters
# -------------------------------------------------------------
ALIVE_GREP="phase1_alive.gnmap"
LIVE_LIST="live_hosts.tmp"

# Phase2a files
NMAP_TCP_GREP="phase2a_nmap_top1000.gnmap"
MASSCAN_TCP_RAW="phase2a_masscan_all.txt"
TCP_LIST="phase2a_tcp_list.txt"

# Phase2b files
UDP_GREP="phase2b_udp.gnmap"
UDP_LIST="phase2b_udp_list.txt"

# Combined results
COMBINED="phase3_combined.txt"
ALL_PORTS="phase4_all_ports.txt"

# Phase4 output
DETAILED_DIR="phase4_details"

# Ranges & rates
TCP_NMAP_TOP=1000  #default 1000, but use 1 for testing
MASSCAN_RATE=1000  #default 1000, but use 5000 or 10000 for testing
MASSCAN_PORT_RANGE="-p1-p65535" #default -p1-p65535, but use -p1-p100 for testing
UDP_TOP=1000       #default 1000, but use 1 for testing
NMAP_T=4
STAT_INTERVAL="30s"

# -------------------------------------------------------------
# PHASE 1: Discover live hosts
# -------------------------------------------------------------
echo "=== Phase 1: Discover live hosts ==="
PHASE1_COMMAND="nmap -sn -PR -PE -PS80,443 -PU53 -iL \"$TARGETS\" -oG \"$ALIVE_GREP\""
echo
echo "Running: "
echo "  $PHASE1_COMMAND"
echo

nmap -sn -PR -PE -PS80,443 -PU53 -iL "$TARGETS" -oG "$ALIVE_GREP"

awk '/Up$/{print $2}' "$ALIVE_GREP" | sort -u > "$LIVE_LIST"
if [[ ! -s $LIVE_LIST ]]; then
  echo "[!] No live hosts."
  exit 0
fi
echo "Live hosts:"
sed 's/^/  /' "$LIVE_LIST"

# -------------------------------------------------------------
# PHASE 2a-A: Nmap top-1000 TCP SYN scan with stats every 60s
# -------------------------------------------------------------
echo
echo "=== Phase 2a-A: Nmap TCP top-$TCP_NMAP_TOP with stats every $STAT_INTERVAL ==="
PHASE_2aA_COMMAND="nmap -Pn -sS --top-ports $TCP_NMAP_TOP -T$NMAP_T --open --stats-every $STAT_INTERVAL -iL \"$LIVE_LIST\" -Og \"$NMAP_TCP_GREP\""

echo
echo "Running: "
echo "  $PHASE_2aA_COMMAND"
echo

nmap -Pn -sS --top-ports $TCP_NMAP_TOP -T$NMAP_T --open \
  --stats-every $STAT_INTERVAL \
  -iL "$LIVE_LIST" -oG "$NMAP_TCP_GREP"

# parse Nmap results
awk '/\/open\/tcp/ {
  host=$2
  for(i=1;i<=NF;i++){
    if($i ~ /\/open\/tcp/){
      split($i,f,"/")
      print host ":" f[1]
    }
  }
}' "$NMAP_TCP_GREP" | sort -u > "$TCP_LIST"

# -------------------------------------------------------------
# PHASE 2a-B: Masscan full-range with status every 30s
# -------------------------------------------------------------
echo
echo "=== Phase 2a-B: Masscan TCP $MASSCAN_PORT_RANGE @${MASSCAN_RATE}pps with status every 30s ==="

PHASE_2aB_COMMAND="sudo masscan $MASSCAN_PORT_RANGE --rate \"$MASSCAN_RATE\" -iL \"$LIVE_LIST\" --open-only -oL \"$MASSCAN_TCP_RAW\" || echo \"[!] masscan exicted with code $?\""

echo
echo "Running: "
echo "  $PHASE_2aB_COMMAND"
echo


sudo masscan $MASSCAN_PORT_RANGE --rate "$MASSCAN_RATE" \
  -iL "$LIVE_LIST" --open-only \
  -oL "$MASSCAN_TCP_RAW" -v || echo "[!] masscan exited with code $?"

# parse Masscan results
awk '/open tcp/ { print $4 ":" $3 }' "$MASSCAN_TCP_RAW" | sort -u >> "$TCP_LIST"
sort -u "$TCP_LIST" -o "$TCP_LIST"

echo "Combined TCP open ports:"
sed 's/^/  /' "$TCP_LIST" || echo "  (none)"

# -------------------------------------------------------------
# PHASE 2b: UDP sweep
# -------------------------------------------------------------
echo
echo "=== Phase 2b: UDP sweep top-$UDP_TOP ==="

PHASE_2b_COMMAND="nmap -Pn -sU -T$NMAP_T --top-ports $UDP_TOP --open \ -iL \"$LIVE_LIST\" -oG \"$UDP_GREP\""

echo
echo "Running: "
echo "  $PHASE_2b_COMMAND"
echo

nmap -Pn -sU -T$NMAP_T --top-ports $UDP_TOP --open \
  -iL "$LIVE_LIST" -oG "$UDP_GREP" --host-timeout 1m --max-retries 1 --min-rate 500 --stats-every 30s

awk '/\/open\|filtered\/udp/ || /\/open\/udp/ {
  host=$2
  for(i=1;i<=NF;i++){
    if($i ~ /udp$/ && ($i ~ /open\/udp/ || $i ~ /open\|filtered\/udp/)){
      split($i,f,"/")
      print host ":" f[1]
    }
  }
}' "$UDP_GREP" | sort -u > "$UDP_LIST"

echo "UDP open ports:"
sed 's/^/  /' "$UDP_LIST" || echo "  (none)"

# -------------------------------------------------------------
# PHASE 3: Consolidate TCP+UDP
# -------------------------------------------------------------
echo
echo "=== Phase 3: Consolidate discovered ports ==="
cat "$TCP_LIST" "$UDP_LIST" | sort -u > "$COMBINED"
echo "All discovered host:port pairs:"
sed 's/^/  /' "$COMBINED" || echo "  (none)"

# build the full comma-separated port list
awk -F: '{print $2}' "$COMBINED" | sort -nu | paste -sd, - > "$ALL_PORTS"
echo "All unique ports to scan in Phase 4:"
sed 's/^/  /' "$ALL_PORTS"

# -------------------------------------------------------------
# PHASE 4: Detailed scan of ALL hosts on ALL ports
# -------------------------------------------------------------
echo
echo "=== Phase 4: Scanning all live hosts on all discovered ports ==="

PORTS=$(<"$ALL_PORTS")

PHASE4_COMMAND="nmap -A -T$NMAP_T -p \"$PORTS\" -iL \"$LIVE_LIST\" \
-oA \"$DETAILED_DIR/all_hosts\" --stats-every $STAT_INTERVAL\""

echo
echo "Running: "
echo "  $PHASE4_COMMAND"
echo

mkdir -p "$DETAILED_DIR"

nmap -A -T$NMAP_T -p "$PORTS" -iL "$LIVE_LIST" -oA "$DETAILED_DIR/all_hosts" \
  --stats-every $STAT_INTERVAL

echo "Results saved in $DETAILED_DIR/all_hosts.[nmap|gnmap|xml]"

echo
echo "[✓] Done."
echo " • phase1: $ALIVE_GREP"
echo " • phase2a-nmap: $NMAP_TCP_GREP"
echo " • phase2a-masscan: $MASSCAN_TCP_RAW"
echo " • phase2a-list: $TCP_LIST"
echo " • phase2b-udp: $UDP_GREP / $UDP_LIST"
echo " • phase3: $COMBINED"
echo " • phase4-all: $DETAILED_DIR/all_hosts.*"

echo
echo "Creating CSV of all discovered services for manual analysis:"
./nmap_to_csv.sh

echo
echo "Running gowitness scan on discovered services:"
# gowitness scan nmap -f phase4_details/all_hosts.xml --write-db
gowitness scan nmap -f $DETAILED_DIR/all_hosts.xml --write-db

echo
echo "Generating list of webapps discovered from gowitness results:"
sudo gowitness report list | grep http | awk {'print $10'} > webapps.txt
cat webapps.txt

echo
echo "Running nuclei scan on all discovered webapps:"
sudo nuclei -list webapps.txt -si 60 -ts -stats -o nuclei_output.txt

echo
echo "done with initial recon?"
