#!/usr/bin/env bash
#
# discovery.sh
#
# Phased, resumable host discovery with full logging.
# Use networks.txt to define subnets (one per line); if missing, auto-generate.
# Tracks completed subnets in networks.done to resume after crash.
# Usage: sudo ./discovery.sh [-v]

set -euo pipefail

VERBOSE=0
OUTPUT="targets.txt"
LOG="scan.log"
DONE="networks.done"
NETWORKS="networks.txt"
trap 'exit' INT

# parse flags
while [[ $# -gt 0 ]]; do
  case "$1" in
    -v) VERBOSE=1; shift;;
    -h|--help) echo "Usage: $0 [-v]" >&2; exit 1;;
    *) echo "Unknown option: $1" >&2; exit 1;;
  esac
done

# set up logging: tee both stdout and stderr to log file
touch "$LOG"
exec > >(tee -a "$LOG") 2>&1

log(){ printf '%s [*] %s\n' "$(date +'%Y-%m-%d %H:%M:%S')" "$*"; }
debug(){ (( VERBOSE )) && printf '%s [D] %s\n' "$(date +'%H:%M:%S')" "$*"; }

# detect interface and local CIDR
CIDR=$(ip -4 route show scope link | awk '/proto kernel|default/ {print $1; exit}')
IFACE=$(ip -4 route get "${CIDR%%/*}" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
log "Using $IFACE on $CIDR"

# prepare output and seen IPs
touch "$OUTPUT"
declare -A seen
while read -r ip; do seen["$ip"]=1; done < "$OUTPUT"

# generate networks.txt if missing, sorted smallest-to-largest subnets
generate_networks(){
  echo "$CIDR" > "$NETWORKS"
  ip route show | awk '/via/ && $1 ~ /^[0-9]+\/[0-9]+/ {print $1}' >> "$NETWORKS"
  cat <<EOF >> "$NETWORKS"
10.0.0.0/24
172.16.0.0/24
192.168.0.0/24
10.0.0.0/16
172.16.0.0/16
192.168.0.0/16
EOF
  sort -t/ -k2,2nr -u "$NETWORKS" -o "$NETWORKS"
}
[[ -f "$NETWORKS" ]] || generate_networks

# load or init done-list
touch "$DONE"
declare -A done
while read -r net; do done["$net"]=1; done < "$DONE"

# helper to record hosts (only once)
record(){ local ip="$1"
  if [[ -z ${seen[$ip]+x} ]]; then
    seen["$ip"]=1
    echo "+ $ip"
    echo "$ip" >> "$OUTPUT"
    (( VERBOSE )) && debug "Recorded new host $ip"
  fi
}

# scan a single network
scan(){ local net="$1"
  log "Scanning $net"
  prefix=${net#*/}

  if (( prefix == 24 )) && command -v arp-scan &>/dev/null; then
    debug "arp-scan on $net"
    while read -r ip; do
      record "$ip"
    done < <(arp-scan --interface="$IFACE" "$net" 2>/dev/null \
      | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}') || true
  fi

  if command -v fping &>/dev/null; then
    debug "fping on $net"
    set +e
    while read -r ip; do
      record "$ip"
    done < <(fping -a -g "$net" 2>/dev/null) || true
    set -e
  fi

  if command -v nmap &>/dev/null; then
    debug "nmap ping on $net"
    while read -r ip; do
      record "$ip"
    done < <(nmap -sn -PS22,80,443 "$net" -T4 --max-retries 1 2>/dev/null \
      | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}') || true
  fi

  echo "$net" >> "$DONE"
}

# iterate networks and resume
while read -r net; do
  [[ -n ${done[$net]:-} ]] && debug "Skipping $net (already done)" && continue
  scan "$net"
done < "$NETWORKS"

log "Complete: $(wc -l < "$OUTPUT") hosts in $OUTPUT"
