#!/bin/sh
# Routing & DNS Redirect management for Huawei B310s-927 (Transparent Proxy)
# Usage: net.sh {start|stop|status} [server_ip]

ACTION="$1"
SERVER_IP="$2"
XRAY_TCP_PORT=12345
XRAY_DNS_PORT=12353

has_tcp_rule() {
    iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "XRAY"
}

has_dns_rule() {
    iptables -t nat -L PREROUTING -n 2>/dev/null | grep -q "redir ports $XRAY_DNS_PORT"
}

case "$ACTION" in
  start)
    # 1. Setup Chain NAT TCP
    iptables -t nat -N XRAY 2>/dev/null
    iptables -t nat -F XRAY
    iptables -t nat -A XRAY -d 0.0.0.0/8 -j RETURN
    iptables -t nat -A XRAY -d 127.0.0.0/8 -j RETURN
    iptables -t nat -A XRAY -d 169.254.0.0/16 -j RETURN
    iptables -t nat -A XRAY -d 192.168.0.0/16 -j RETURN
    iptables -t nat -A XRAY -d 224.0.0.0/4 -j RETURN
    iptables -t nat -A XRAY -d 240.0.0.0/4 -j RETURN

    # Bypass VPS Server IP(s) to prevent routing loop (pure POSIX sh, no tr needed)
    if [ -n "$SERVER_IP" ]; then
        OLD_IFS="$IFS"
        IFS=','
        for ip in $SERVER_IP; do
            [ -n "$ip" ] && iptables -t nat -A XRAY -d "$ip" -j RETURN
        done
        IFS="$OLD_IFS"
    fi

    iptables -t nat -A XRAY -p tcp -j REDIRECT --to-ports $XRAY_TCP_PORT

    # Attach to PREROUTING if not already present
    if ! has_tcp_rule; then
        iptables -t nat -A PREROUTING -p tcp -j XRAY
    fi

    # 2. Redirect DNS (UDP 53) to Xray DNS Inbound
    if ! has_dns_rule; then
        iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports $XRAY_DNS_PORT
    fi
    ;;

  stop)
    while iptables -t nat -D PREROUTING -p tcp -j XRAY 2>/dev/null; do :; done
    while iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports $XRAY_DNS_PORT 2>/dev/null; do :; done
    iptables -t nat -F XRAY 2>/dev/null
    iptables -t nat -X XRAY 2>/dev/null
    ;;

  status)
    if has_tcp_rule && has_dns_rule; then
        echo "active"
        exit 0
    else
        echo "inactive"
        exit 1
    fi
    ;;

  *)
    echo "Usage: $0 {start|stop|status} [server_ip]"
    exit 1
    ;;
esac
