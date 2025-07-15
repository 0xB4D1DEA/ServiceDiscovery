#!/usr/bin/env bash

REPO_URL="https://github.com/0xB4D1DEA/Nmap-Scan-to-CSV"
LOCAL_DIR="Nmap-Scan-to-CSV"

INPUT_XML="phase4_details/all_hosts.xml"
OUTPUT_CSV="phase4_details/all_hosts.csv"

# Clone or update repo
if [ ! -d "$LOCAL_DIR" ]; then
  echo "[+] Cloning $REPO_URL ..."
  git clone "$REPO_URL" "$LOCAL_DIR"
else
  echo "[+] Repo already exists. Pulling latest changes..."
  git -C "$LOCAL_DIR" pull
fi

# Check input file
if [ ! -f "$INPUT_XML" ]; then
  echo "[!] ERROR: Input file '$INPUT_XML' does not exist."
  exit 1
fi

# Run the parser with proper flags
echo "[+] Converting $INPUT_XML -> $OUTPUT_CSV ..."
python3 "$LOCAL_DIR/nmap_xml_parser.py" -f "$INPUT_XML" -csv "$OUTPUT_CSV"

echo "[✓] Done! CSV saved to $OUTPUT_CSV"
