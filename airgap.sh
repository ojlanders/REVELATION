#!/bin/bash
set -e

error_exit() {
    echo "Error: $1" >&2
    exit 1
}

if [[ "$EUID" -ne 0 ]]; then
    error_exit "This script must be run as root."
fi

apply_nftables_airgap() {
    echo "Applying airgap rules using nftables..."
    nft flush ruleset
    nft add table inet filter
    nft add chain inet filter input { type filter hook input priority 0 \; policy drop \; }
    nft add chain inet filter forward { type filter hook forward priority 0 \; policy drop \; }
    nft add chain inet filter output { type filter hook output priority 0 \; policy drop \; }
    nft add rule inet filter input iif "lo" accept
    nft add rule inet filter output oif "lo" accept
    echo "nftables airgap rules applied successfully."
}

apply_iptables_airgap() {
    echo "Applying airgap rules using iptables..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    echo "iptables airgap rules applied successfully."
}

if command -v nft >/dev/null 2>&1; then
    apply_nftables_airgap
elif command -v iptables >/dev/null 2>&1; then
    apply_iptables_airgap
else
    error_exit "Neither nftables nor iptables is installed on this system."
fi

echo "Machine has been successfully airgapped."

