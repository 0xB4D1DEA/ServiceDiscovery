#!/bin/bash

# Automated Nmap and Masscan Scanning Script

# Usage: ./scan.sh targets.txt output_directory

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 targets.txt output_directory"
    exit 1
fi

TARGETS_FILE="$1"
OUTPUT_DIR="$2"

mkdir -p "$OUTPUT_DIR"

# Resolve hostnames to IPs if necessary
echo "[+] Resolving hostnames to IP addresses..."
RESOLVED_TARGETS="$OUTPUT_DIR/resolved_targets.txt"
> "$RESOLVED_TARGETS"

while IFS= read -r target; do
    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$target" >> "$RESOLVED_TARGETS"
    else
        ip=$(dig +short "$target" | grep -E '^[0-9.]+$' | head -n 1)
        if [ -n "$ip" ]; then
            echo "$ip" >> "$RESOLVED_TARGETS"
            echo "[+] Resolved $target to $ip"
        else
            echo "[-] Failed to resolve $target"
        fi
    fi
done < "$TARGETS_FILE"

# Step 1: Host discovery using ping scan
echo "[+] Starting host discovery with ping scan..."
nmap -sn -iL "$RESOLVED_TARGETS" -oG "$OUTPUT_DIR/ping_discovery.gnmap"

# Extract online hosts from ping scan output
ONLINE_HOSTS="$OUTPUT_DIR/online_hosts.txt"
grep 'Status: Up' "$OUTPUT_DIR/ping_discovery.gnmap" | awk '{print $2}' | sort -u > "$ONLINE_HOSTS"

# Step 2: Nmap top 1000 TCP ports scan
echo "[+] Running Nmap for top 1000 TCP ports..."
nmap -iL "$ONLINE_HOSTS" --top-ports 1000 -oA "$OUTPUT_DIR/nmap_top1000_tcp"

# Step 3: Nmap top 1000 UDP ports scan
echo "[+] Running Nmap for top 1000 UDP ports..."
nmap -iL "$ONLINE_HOSTS" -sU --top-ports 1000 -oA "$OUTPUT_DIR/nmap_top1000_udp"

# Step 4: Masscan for all ports on online hosts
echo "[+] Running Masscan for all ports on online hosts..."
masscan -iL "$ONLINE_HOSTS" -p1-65535 --rate=2500 -oG "$OUTPUT_DIR/masscan_all_ports.gnmap"

# Extract unique open ports from Masscan and Nmap outputs
OPEN_PORTS="$OUTPUT_DIR/open_ports.txt"
grep 'open' "$OUTPUT_DIR/masscan_all_ports.gnmap" | awk '{print $4}' | sort -u > "$OPEN_PORTS"
grep 'open' "$OUTPUT_DIR/nmap_top1000_tcp.gnmap" | awk '{print $4}' | sort -u >> "$OPEN_PORTS"
grep 'open' "$OUTPUT_DIR/nmap_top1000_udp.gnmap" | awk '{print $4}' | sort -u >> "$OPEN_PORTS"
sort -u -o "$OPEN_PORTS" "$OPEN_PORTS"

# Step 5: Nmap -A scan on identified ports
echo "[+] Running Nmap -A scan on identified ports..."
PORT_LIST=$(paste -sd, "$OPEN_PORTS")
nmap -iL "$ONLINE_HOSTS" -p "$PORT_LIST" -A -oA "$OUTPUT_DIR/nmap_a_scan"

echo "[+] Scanning complete. Results saved to: $OUTPUT_DIR"
