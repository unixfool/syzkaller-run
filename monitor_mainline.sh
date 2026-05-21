#!/bin/bash
#
# Monitor Linux Kernel MainLine
# ==============================================================================
#    Creador: y2k         → Email: y2k@desarrollaria.com
# ==============================================================================

LINUX_DIR="$HOME/Work/LinuxScan/linux"
LOG="$HOME/Work/LinuxScan/output/monitor-6.12.89.log"
ALERT="$HOME/Work/LinuxScan/output/alerts.txt"

cd "$LINUX_DIR" || exit 1

git fetch origin --quiet 2>/dev/null

LAST=$(cat /tmp/last_mainline_commit 2>/dev/null || git rev-parse v6.12.89)
NEW=$(git log origin/master "$LAST"..origin/master --oneline 2>/dev/null)

if [ -z "$NEW" ]; then
    exit 0
fi

git rev-parse origin/master > /tmp/last_mainline_commit

# Subsistemas validos en kernelCTF lts-6.12:
# - perf_events (CONFIG_PERF_EVENTS=y)
# - futex (CONFIG_FUTEX=y)
# - TCP/IPv4/IPv6 sin CAP_NET_ADMIN
# - UNIX sockets
# Excluidos: io_uring (deshabilitado), nftables (deshabilitado),
#            BPF (unprivileged=2), user namespaces (deshabilitado)
INTERESTING=$(echo "$NEW" | \
  grep -iE "uaf|use-after-free|use after free|double.free|slab-out-of-bounds|oob write|overflow" | \
  grep -iE "perf_event|perf/core|futex|unix socket|af_unix|ipv4|ipv6|tcp|udp" | \
  grep -viE "^Merge|annotate|annotation|data-race|comment|cleanup|spelling|typo|\
io_uring|bpf|tls|netfilter|nftables|calipso|sctp|dccp|tipc|bluetooth|wifi|\
nvme|nvmet|mptcp|smc|bareudp|IB/|CAP_NET_ADMIN|netlink|rtnetlink|\
nexthop|ioam|rpl|geneve|vxlan|tunnel|offload")

if [ -z "$INTERESTING" ]; then
    exit 0
fi

while IFS= read -r line; do
    HASH=$(echo "$line" | awk '{print $1}')
    MSG=$(echo "$line" | cut -d' ' -f2-)

    # Verificar que el fix NO esta en 6.12.89
    if ! git log v6.12.89 --oneline | grep -q "$HASH"; then
        # Verificar que no requiere privilegios revisando el diff
        DIFF=$(git show "$HASH" -- 2>/dev/null | head -100)
        # Excluir si el diff menciona CAP_ requirements o admin interfaces
        if ! echo "$DIFF" | grep -qiE "CAP_NET_ADMIN|CAP_SYS_ADMIN|CAP_NET_RAW|ns_capable|rtnetlink_rcv|ndo_|rtnl_lock"; then
            TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
            echo "[$TIMESTAMP] CANDIDATO: $HASH $MSG" | tee -a "$ALERT"
        else
            TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
            echo "[$TIMESTAMP] DESCARTADO (privilegios): $HASH $MSG" >> "$LOG"
        fi
    fi
done <<< "$INTERESTING"
