import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from collections import defaultdict, Counter
from datetime import datetime
import math
import os


class PCAPAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.packets = []
        self.findings = []
        self.stats = {}

    def load(self):
        """Load packets from PCAP file."""
        self.packets = scapy.rdpcap(self.filepath)

    def run(self):
        """Run all detection modules and return results."""
        self.load()

        if not self.packets:
            return {
                'error': 'No packets found in file',
                'filename': self.filename,
                'findings': [],
                'stats': {},
                'summary': {}
            }

        self._compute_stats()
        self._detect_port_scan()
        self._detect_arp_spoofing()
        self._detect_dns_anomalies()
        self._detect_brute_force()
        self._detect_icmp_flood()
        self._detect_suspicious_protocols()
        self._detect_large_transfers()

        # Sort findings by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        self.findings.sort(key=lambda x: severity_order.get(x['severity'], 5))

        summary = self._build_summary()

        return {
            'filename': self.filename,
            'findings': self.findings,
            'stats': self.stats,
            'summary': summary
        }

    def _compute_stats(self):
        """Compute general packet statistics."""
        total = len(self.packets)
        protocols = Counter()
        src_ips = Counter()
        dst_ips = Counter()
        start_time = None
        end_time = None

        for pkt in self.packets:
            ts = float(pkt.time)
            if start_time is None or ts < start_time:
                start_time = ts
            if end_time is None or ts > end_time:
                end_time = ts

            if pkt.haslayer(TCP):
                protocols['TCP'] += 1
            elif pkt.haslayer(UDP):
                protocols['UDP'] += 1
            elif pkt.haslayer(ICMP):
                protocols['ICMP'] += 1
            elif pkt.haslayer(ARP):
                protocols['ARP'] += 1
            else:
                protocols['Other'] += 1

            if pkt.haslayer(IP):
                src_ips[pkt[IP].src] += 1
                dst_ips[pkt[IP].dst] += 1

        duration = round(end_time - start_time, 2) if (start_time and end_time) else 0
        top_talkers = [{'ip': ip, 'count': count} for ip, count in src_ips.most_common(5)]
        top_targets = [{'ip': ip, 'count': count} for ip, count in dst_ips.most_common(5)]

        self.stats = {
            'total_packets': total,
            'duration_seconds': duration,
            'protocols': dict(protocols),
            'unique_src_ips': len(src_ips),
            'unique_dst_ips': len(dst_ips),
            'top_talkers': top_talkers,
            'top_targets': top_targets,
            'capture_start': datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S') if start_time else 'Unknown',
        }

    def _detect_port_scan(self):
        """Detect port scanning activity (horizontal and vertical)."""
        # Vertical scan: one source hitting many ports on one destination
        src_dst_ports = defaultdict(lambda: defaultdict(set))
        syn_counts = defaultdict(lambda: defaultdict(int))

        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                flags = pkt[TCP].flags
                src = pkt[IP].src
                dst = pkt[IP].dst
                dport = pkt[TCP].dport

                src_dst_ports[src][dst].add(dport)

                # SYN without ACK = scan probe
                if flags == 0x02:
                    syn_counts[src][dst] += 1

        scanners = []
        for src, targets in src_dst_ports.items():
            for dst, ports in targets.items():
                if len(ports) > 15:
                    scanners.append({
                        'src': src,
                        'dst': dst,
                        'ports_scanned': len(ports),
                        'port_sample': sorted(list(ports))[:10]
                    })

        # Horizontal scan: one source hitting many destinations on same port
        src_port_dsts = defaultdict(lambda: defaultdict(set))
        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                if pkt[TCP].flags == 0x02:
                    src = pkt[IP].src
                    dport = pkt[TCP].dport
                    dst = pkt[IP].dst
                    src_port_dsts[src][dport].add(dst)

        h_scanners = []
        for src, ports in src_port_dsts.items():
            for port, dsts in ports.items():
                if len(dsts) > 10:
                    h_scanners.append({'src': src, 'port': port, 'hosts_scanned': len(dsts)})

        if scanners:
            for s in scanners:
                self.findings.append({
                    'severity': 'HIGH',
                    'category': 'Reconnaissance',
                    'title': 'Vertical Port Scan Detected',
                    'description': f'{s["src"]} scanned {s["ports_scanned"]} ports on {s["dst"]}. Sample ports: {s["port_sample"]}',
                    'count': s['ports_scanned'],
                    'indicator': f'{s["src"]} → {s["dst"]}'
                })

        if h_scanners:
            for s in h_scanners:
                self.findings.append({
                    'severity': 'HIGH',
                    'category': 'Reconnaissance',
                    'title': 'Horizontal Port Scan Detected',
                    'description': f'{s["src"]} probed port {s["port"]} on {s["hosts_scanned"]} different hosts — indicative of network-wide service discovery.',
                    'count': s['hosts_scanned'],
                    'indicator': f'{s["src"]} → port {s["port"]}'
                })

    def _detect_arp_spoofing(self):
        """Detect ARP spoofing by finding conflicting IP-to-MAC mappings."""
        arp_table = defaultdict(set)

        for pkt in self.packets:
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:  # ARP reply
                ip = pkt[ARP].psrc
                mac = pkt[ARP].hwsrc
                arp_table[ip].add(mac)

        conflicts = {ip: macs for ip, macs in arp_table.items() if len(macs) > 1}

        if conflicts:
            for ip, macs in conflicts.items():
                self.findings.append({
                    'severity': 'CRITICAL',
                    'category': 'Network Attack',
                    'title': 'ARP Spoofing Detected',
                    'description': f'IP {ip} is being claimed by {len(macs)} different MAC addresses: {", ".join(macs)}. This is a strong indicator of an ARP poisoning / Man-in-the-Middle attack.',
                    'count': len(macs),
                    'indicator': ip
                })

    def _detect_dns_anomalies(self):
        """Detect DNS tunneling and unusually long domain queries."""
        dns_queries = defaultdict(list)
        long_queries = []
        high_entropy_queries = []

        for pkt in self.packets:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                try:
                    qname = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                    src = pkt[IP].src if pkt.haslayer(IP) else 'Unknown'
                    dns_queries[src].append(qname)

                    # Long subdomain = possible DNS tunneling
                    parts = qname.split('.')
                    if parts:
                        subdomain = parts[0]
                        if len(subdomain) > 40:
                            long_queries.append({'src': src, 'query': qname})

                        # High Shannon entropy in subdomain = encoded data
                        if len(subdomain) > 20:
                            entropy = self._shannon_entropy(subdomain)
                            if entropy > 3.8:
                                high_entropy_queries.append({'src': src, 'query': qname, 'entropy': round(entropy, 2)})
                except Exception:
                    continue

        # Many unique queries from one host = possible DGA or tunneling
        for src, queries in dns_queries.items():
            unique = len(set(queries))
            if unique > 100:
                self.findings.append({
                    'severity': 'MEDIUM',
                    'category': 'DNS Anomaly',
                    'title': 'Excessive DNS Queries',
                    'description': f'{src} made {unique} unique DNS queries. This may indicate Domain Generation Algorithm (DGA) malware or DNS tunneling.',
                    'count': unique,
                    'indicator': src
                })

        if long_queries:
            seen = set()
            for q in long_queries:
                if q['src'] not in seen:
                    seen.add(q['src'])
                    self.findings.append({
                        'severity': 'HIGH',
                        'category': 'DNS Anomaly',
                        'title': 'Suspiciously Long DNS Query',
                        'description': f'Host {q["src"]} made a DNS query with an unusually long subdomain ({len(q["query"])} chars). This is a common DNS tunneling technique.',
                        'count': len(q['query']),
                        'indicator': q['query'][:80] + '...' if len(q['query']) > 80 else q['query']
                    })

        if high_entropy_queries:
            seen = set()
            for q in high_entropy_queries:
                if q['src'] not in seen:
                    seen.add(q['src'])
                    self.findings.append({
                        'severity': 'HIGH',
                        'category': 'DNS Anomaly',
                        'title': 'High-Entropy DNS Query (Possible Tunneling)',
                        'description': f'Host {q["src"]} queried a domain with high Shannon entropy ({q["entropy"]}). Encoded data in DNS subdomains is a known data exfiltration technique.',
                        'count': q['entropy'],
                        'indicator': q['query'][:80]
                    })

    def _detect_brute_force(self):
        """Detect SSH, FTP, and HTTP brute force attempts."""
        # SSH brute force: many TCP connections to port 22 from same source
        ssh_attempts = defaultdict(lambda: defaultdict(int))
        ftp_attempts = defaultdict(lambda: defaultdict(int))
        http_attempts = defaultdict(lambda: defaultdict(int))

        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                if pkt[TCP].flags == 0x02:  # SYN
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    dport = pkt[TCP].dport

                    if dport == 22:
                        ssh_attempts[src][dst] += 1
                    elif dport == 21:
                        ftp_attempts[src][dst] += 1
                    elif dport in (80, 443, 8080, 8443):
                        http_attempts[src][dst] += 1

        for service, attempts, threshold in [
            ('SSH (port 22)', ssh_attempts, 10),
            ('FTP (port 21)', ftp_attempts, 10),
            ('HTTP/HTTPS', http_attempts, 50)
        ]:
            for src, targets in attempts.items():
                for dst, count in targets.items():
                    if count >= threshold:
                        self.findings.append({
                            'severity': 'HIGH',
                            'category': 'Brute Force',
                            'title': f'{service} Brute Force Attempt',
                            'description': f'{src} made {count} connection attempts to {service} on {dst}. This exceeds the threshold for normal behaviour and suggests a credential stuffing or brute force attack.',
                            'count': count,
                            'indicator': f'{src} → {dst}'
                        })

    def _detect_icmp_flood(self):
        """Detect ICMP flood (DoS) attacks."""
        icmp_counts = defaultdict(lambda: defaultdict(int))

        for pkt in self.packets:
            if pkt.haslayer(ICMP) and pkt.haslayer(IP):
                if pkt[ICMP].type == 8:  # Echo request
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    icmp_counts[src][dst] += 1

        for src, targets in icmp_counts.items():
            for dst, count in targets.items():
                if count > 100:
                    self.findings.append({
                        'severity': 'MEDIUM',
                        'category': 'DoS / Flood',
                        'title': 'ICMP Flood Detected',
                        'description': f'{src} sent {count} ICMP echo requests to {dst}. This volume suggests a ping flood / DoS attempt.',
                        'count': count,
                        'indicator': f'{src} → {dst}'
                    })

    def _detect_suspicious_protocols(self):
        """Detect traffic on unusual or suspicious ports."""
        suspicious_ports = {
            4444: ('Metasploit default listener', 'CRITICAL'),
            1337: ('Common backdoor port', 'HIGH'),
            31337: ('Back Orifice / elite hacker port', 'HIGH'),
            6666: ('IRC / botnet C2', 'MEDIUM'),
            6667: ('IRC / botnet C2', 'MEDIUM'),
            8888: ('Common malware C2 port', 'LOW'),
            9001: ('Tor default port', 'MEDIUM'),
            9050: ('Tor SOCKS proxy', 'MEDIUM'),
        }

        port_traffic = defaultdict(lambda: defaultdict(int))

        for pkt in self.packets:
            if pkt.haslayer(TCP) and pkt.haslayer(IP):
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                src = pkt[IP].src
                dst = pkt[IP].dst

                for port in [dport, sport]:
                    if port in suspicious_ports:
                        port_traffic[port][f'{src}→{dst}'] += 1

        for port, connections in port_traffic.items():
            desc, severity = suspicious_ports[port]
            top = sorted(connections.items(), key=lambda x: x[1], reverse=True)[:3]
            self.findings.append({
                'severity': severity,
                'category': 'Suspicious Traffic',
                'title': f'Traffic on Port {port} ({desc})',
                'description': f'Detected {sum(connections.values())} packets on port {port} — {desc}. Top connections: {", ".join([f"{k} ({v} pkts)" for k,v in top])}',
                'count': sum(connections.values()),
                'indicator': f'Port {port}'
            })

    def _detect_large_transfers(self):
        """Flag unusually large data transfers that may indicate exfiltration."""
        src_bytes = defaultdict(int)

        for pkt in self.packets:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                src_bytes[src] += len(pkt)

        for src, total_bytes in src_bytes.items():
            mb = total_bytes / (1024 * 1024)
            if mb > 10:
                self.findings.append({
                    'severity': 'LOW',
                    'category': 'Data Transfer',
                    'title': 'Large Data Volume from Single Host',
                    'description': f'Host {src} generated {mb:.1f} MB of traffic. While not necessarily malicious, large transfers warrant investigation for potential data exfiltration.',
                    'count': round(mb, 1),
                    'indicator': src
                })

    def _build_summary(self):
        severity_counts = Counter(f['severity'] for f in self.findings)
        return {
            'total_findings': len(self.findings),
            'critical': severity_counts.get('CRITICAL', 0),
            'high': severity_counts.get('HIGH', 0),
            'medium': severity_counts.get('MEDIUM', 0),
            'low': severity_counts.get('LOW', 0),
            'info': severity_counts.get('INFO', 0),
            'risk_level': self._overall_risk(severity_counts)
        }

    def _overall_risk(self, counts):
        if counts.get('CRITICAL', 0) > 0:
            return 'CRITICAL'
        elif counts.get('HIGH', 0) > 0:
            return 'HIGH'
        elif counts.get('MEDIUM', 0) > 0:
            return 'MEDIUM'
        elif counts.get('LOW', 0) > 0:
            return 'LOW'
        return 'CLEAN'

    def _shannon_entropy(self, s):
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0
        freq = Counter(s)
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
