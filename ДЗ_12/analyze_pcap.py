import argparse
import json
from collections import Counter
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import pyshark


def safe_get(obj, *names, default=None):
    """Безопасно получить поле из pyshark layer по нескольким возможным именам."""
    for name in names:
        if hasattr(obj, name):
            try:
                value = getattr(obj, name)
                if value is not None and str(value) != "":
                    return str(value)
            except Exception:
                pass
    return default


def parse_packet(pkt):
    """Разбор одного пакета -> словарь события."""
    event = {
        "time": None,
        "event_type": "OTHER",
        "protocol": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "domain": None,
        "details": None,
    }

    try:
        event["time"] = pd.to_datetime(float(pkt.sniff_timestamp), unit="s")
    except Exception:
        event["time"] = pd.NaT

    event["protocol"] = safe_get(pkt, "highest_layer", default="UNKNOWN")

    if "IP" in pkt:
        ip = pkt.ip
        event["src_ip"] = safe_get(ip, "src")
        event["dst_ip"] = safe_get(ip, "dst")
    elif "IPV6" in pkt:
        ip6 = pkt.ipv6
        event["src_ip"] = safe_get(ip6, "src")
        event["dst_ip"] = safe_get(ip6, "dst")

    if "TCP" in pkt:
        tcp = pkt.tcp
        event["src_port"] = safe_get(tcp, "srcport")
        event["dst_port"] = safe_get(tcp, "dstport")
    elif "UDP" in pkt:
        udp = pkt.udp
        event["src_port"] = safe_get(udp, "srcport")
        event["dst_port"] = safe_get(udp, "dstport")

    if "DNS" in pkt:
        dns = pkt.dns
        flags_response = safe_get(dns, "flags_response", "dns_flags_response", default=None)
        is_query = (flags_response == "0") or (flags_response is None)
        qname = safe_get(dns, "qry_name", "dns_qry_name")
        qtype = safe_get(dns, "qry_type", "dns_qry_type")

        event["event_type"] = "DNS_QUERY" if is_query else "DNS_RESPONSE"
        event["domain"] = qname
        event["details"] = f"qtype={qtype}" if qtype else None
        return event

    if "BOOTP" in pkt or "DHCP" in pkt:
        bootp = getattr(pkt, "bootp", None)
        msg_type = None
        if bootp is not None:
            msg_type = safe_get(
                bootp,
                "option_dhcp",
                "option_dhcp_message_type",
                "dhcp_option_dhcp",
                default=None,
            )
            xid = safe_get(bootp, "id", "xid", default=None)
            yiaddr = safe_get(bootp, "ip_your", "yiaddr", default=None)
            chaddr = safe_get(bootp, "hw_mac_addr", "chaddr", default=None)

            parts = []
            if xid:
                parts.append(f"xid={xid}")
            if yiaddr:
                parts.append(f"yiaddr={yiaddr}")
            if chaddr:
                parts.append(f"chaddr={chaddr}")
            event["details"] = ", ".join(parts) if parts else None

        event["event_type"] = "DHCP"
        if msg_type:
            event["details"] = (event["details"] + ", " if event["details"] else "") + f"msg_type={msg_type}"
        return event

    if "ARP" in pkt:
        arp = pkt.arp
        event["event_type"] = "ARP"
        event["src_ip"] = safe_get(arp, "src_proto_ipv4", "src_proto_ipv6", default=event["src_ip"])
        event["dst_ip"] = safe_get(arp, "dst_proto_ipv4", "dst_proto_ipv6", default=event["dst_ip"])
        opcode = safe_get(arp, "opcode", "op")
        if opcode:
            event["details"] = f"opcode={opcode}"
        return event

    return event


def main():
    parser = argparse.ArgumentParser(
        description="Извлечение артефактов из сетевого дампа (pcap/pcapng) с помощью pyshark"
    )
    parser.add_argument("pcap", help="Путь к .pcap/.pcapng")
    parser.add_argument("--out", default="pcap_artifacts", help="Папка для результатов")
    parser.add_argument("--display-filter", default=None, help="Wireshark display filter (необязательно)")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    events = []
    dns_rows = []
    ip_counter = Counter()
    domain_counter = Counter()
    proto_counter = Counter()

    capture = pyshark.FileCapture(
        str(pcap_path),
        keep_packets=False,
        display_filter=args.display_filter,
        use_json=True,
        include_raw=False,
    )

    total_packets = 0
    parse_errors = 0

    try:
        for pkt in capture:
            total_packets += 1
            try:
                evt = parse_packet(pkt)
                events.append(evt)

                if evt["protocol"]:
                    proto_counter[evt["protocol"]] += 1
                if evt["src_ip"]:
                    ip_counter[evt["src_ip"]] += 1
                if evt["dst_ip"]:
                    ip_counter[evt["dst_ip"]] += 1

                if evt["event_type"] == "DNS_QUERY":
                    dns_rows.append(
                        {
                            "time": evt["time"],
                            "src_ip": evt["src_ip"],
                            "dst_ip": evt["dst_ip"],
                            "domain": evt["domain"],
                            "qtype": evt["details"],
                        }
                    )
                    if evt["domain"]:
                        domain_counter[evt["domain"]] += 1

            except Exception:
                parse_errors += 1
    finally:
        capture.close()

    # Таблица событий
    df_events = pd.DataFrame(events)
    if not df_events.empty:
        df_events["time"] = pd.to_datetime(df_events["time"], errors="coerce")
        df_events = df_events.sort_values("time", kind="stable")
    else:
        df_events = pd.DataFrame(columns=[
            "time", "event_type", "protocol", "src_ip", "dst_ip",
            "src_port", "dst_port", "domain", "details"
        ])
    df_events.to_csv(out_dir / "events.csv", index=False, encoding="utf-8")

    df_dns = pd.DataFrame(dns_rows)
    if not df_dns.empty:
        df_dns["time"] = pd.to_datetime(df_dns["time"], errors="coerce")
        df_dns = df_dns.sort_values("time", kind="stable")
    df_dns.to_csv(out_dir / "dns_requests.csv", index=False, encoding="utf-8")

    top_ips = [{"ip": ip, "count": cnt} for ip, cnt in ip_counter.most_common(20)]
    top_domains = [{"domain": d, "count": c} for d, c in domain_counter.most_common(20)]
    top_protocols = [{"protocol": p, "count": c} for p, c in proto_counter.most_common(20)]

    suspicious = []
    for domain, cnt in domain_counter.items():
        if domain is None:
            continue
        reasons = []
        if len(domain) > 50:
            reasons.append("очень длинное доменное имя")
        if domain.count(".") >= 4:
            reasons.append("много уровней домена")
        if sum(ch.isdigit() for ch in domain) >= 6:
            reasons.append("много цифр в домене")
        if reasons:
            suspicious.append({"type": "domain", "value": domain, "count": cnt, "reasons": reasons})

    # График по времени
    plot_path = None
    if not df_dns.empty and df_dns["time"].notna().any():
        s = df_dns.set_index("time").resample("1min").size()
        s.to_csv(out_dir / "dns_count_by_minute.csv", header=["count"], encoding="utf-8")

        plt.figure(figsize=(10, 4))
        s.plot()
        plt.title("Количество DNS-запросов по времени (по минутам)")
        plt.xlabel("Время")
        plt.ylabel("Количество")
        plt.tight_layout()

        plot_path = out_dir / "dns_count_by_minute.png"
        plt.savefig(plot_path, dpi=150)
        plt.close()
    elif not df_events.empty and df_events["time"].notna().any():
        s = df_events.set_index("time").resample("1min").size()
        s.to_csv(out_dir / "events_count_by_minute.csv", header=["count"], encoding="utf-8")

        plt.figure(figsize=(10, 4))
        s.plot()
        plt.title("Количество событий по времени (DNS отсутствуют)")
        plt.xlabel("Время")
        plt.ylabel("Количество")
        plt.tight_layout()

        plot_path = out_dir / "events_count_by_minute.png"
        plt.savefig(plot_path, dpi=150)
        plt.close()

    summary = {
        "input_file": str(pcap_path),
        "total_packets_seen": total_packets,
        "parse_errors": parse_errors,
        "events_total": int(len(df_events)),
        "dns_queries_total": int((df_events["event_type"] == "DNS_QUERY").sum()) if not df_events.empty else 0,
        "unique_ips": int(len(ip_counter)),
        "unique_domains": int(len(domain_counter)),
        "top_protocols": top_protocols,
        "top_ips": top_ips,
        "top_domains": top_domains,
        "suspicious_indicators": suspicious,
        "output_files": {
            "events_csv": str(out_dir / "events.csv"),
            "dns_requests_csv": str(out_dir / "dns_requests.csv"),
            "summary_json": str(out_dir / "summary.json"),
            "plot_png": str(plot_path) if plot_path else None,
        },
    }

    with open(out_dir / "summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2, default=str)

    print("=" * 70)
    print(f"Файл: {pcap_path}")
    print(f"Пакетов обработано: {total_packets}")
    print(f"Событий: {len(df_events)}")
    print(f"DNS-запросов: {summary['dns_queries_total']}")
    print(f"Уникальных IP: {summary['unique_ips']}")
    print(f"Уникальных доменов: {summary['unique_domains']}")
    if top_protocols:
        print("Топ протоколов:", ", ".join(f"{x['protocol']}={x['count']}" for x in top_protocols[:5]))
    print(f"Результаты сохранены в: {out_dir.resolve()}")
    print("=" * 70)


if __name__ == "__main__":
    main()