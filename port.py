#!/usr/bin/env python3
"""
Port Tarayıcı (Port Scanner)
----------------------------
Hedef bir IP adresindeki (veya hostname'deki) açık portları bulmak ve
çalışan servisleri tespit etmek için kullanılan basit bir güvenlik
denetim aracı.

KULLANIM NOTU:
Bu aracı SADECE sahibi olduğunuz veya tarama izniniz olan sistemler
üzerinde kullanın (ör. kendi lab ortamınız, BOTAŞ staj kapsamında size
verilen izinli test ortamı, TryHackMe/HackTheBox gibi izinli platformlar).
İzinsiz sistemleri taramak birçok ülkede (Türkiye'de 5651 sayılı kanun
kapsamında) suç teşkil edebilir.

Kullanım örnekleri:
    python3 port_scanner.py 192.168.1.1
    python3 port_scanner.py 192.168.1.1 -p 1-1000
    python3 port_scanner.py scanme.nmap.org -p 20,21,22,80,443
    python3 port_scanner.py 10.0.0.5 -p 1-65535 -t 200 --timeout 0.5
"""

import argparse
import socket
import sys
import threading
import queue
import time
from datetime import datetime

# En sık kullanılan portlar için basit bir servis sözlüğü
# (banner grabbing başarısız olursa yedek olarak kullanılır)
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
    139: "NetBIOS-SSN", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle-DB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def parse_ports(port_arg: str):
    """'80,443' veya '1-1000' veya '22,80,1000-2000' gibi girdileri port listesine çevirir."""
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            start, end = int(start), int(end)
            if start < 1 or end > 65535 or start > end:
                raise ValueError(f"Geçersiz port aralığı: {part}")
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                raise ValueError(f"Geçersiz port: {p}")
            ports.add(p)
    return sorted(ports)


def grab_banner(sock: socket.socket) -> str:
    """Bağlantı açıldıktan sonra servis banner'ını okumaya çalışır."""
    try:
        sock.settimeout(1.0)
        banner = sock.recv(1024)
        return banner.decode(errors="ignore").strip().split("\n")[0][:80]
    except Exception:
        return ""


def scan_port(target: str, port: int, timeout: float, results: list, lock: threading.Lock):
    """Tek bir portu tarar; açıksa sonucu results listesine ekler."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                # Bazı servisler bağlanır bağlanmaz banner gönderir (FTP, SMTP, SSH gibi)
                banner = grab_banner(sock)
                service = banner if banner else COMMON_PORTS.get(port, "bilinmiyor")
                with lock:
                    results.append((port, service))
    except socket.gaierror:
        print(f"[HATA] Hostname çözümlenemedi: {target}")
        sys.exit(1)
    except Exception:
        pass


def worker(target: str, timeout: float, port_queue: queue.Queue, results: list, lock: threading.Lock):
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return
        scan_port(target, port, timeout, results, lock)
        port_queue.task_done()


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[HATA] '{target}' çözümlenemedi. IP adresi veya geçerli bir hostname girin.")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Basit çok iş parçacıklı (multi-threaded) TCP port tarayıcı."
    )
    parser.add_argument("target", help="Hedef IP adresi veya hostname")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Taranacak portlar. Örn: '80', '1-1000', '22,80,443' (varsayılan: 1-1024)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=100,
        help="Eş zamanlı iş parçacığı sayısı (varsayılan: 100)"
    )
    parser.add_argument(
        "--timeout", type=float, default=1.0,
        help="Her bağlantı denemesi için saniye cinsinden zaman aşımı (varsayılan: 1.0)"
    )
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[HATA] {e}")
        sys.exit(1)

    target_ip = resolve_target(args.target)

    print("=" * 60)
    print(f"  Hedef        : {args.target} ({target_ip})")
    print(f"  Port sayısı  : {len(ports)}")
    print(f"  Thread sayısı: {args.threads}")
    print(f"  Başlangıç    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    port_queue = queue.Queue()
    for p in ports:
        port_queue.put(p)

    results = []
    lock = threading.Lock()
    threads = []

    start_time = time.time()

    thread_count = min(args.threads, len(ports)) or 1
    for _ in range(thread_count):
        th = threading.Thread(
            target=worker,
            args=(target_ip, args.timeout, port_queue, results, lock),
            daemon=True,
        )
        th.start()
        threads.append(th)

    try:
        for th in threads:
            th.join()
    except KeyboardInterrupt:
        print("\n[!] Kullanıcı tarafından durduruldu.")
        sys.exit(1)

    elapsed = time.time() - start_time
    results.sort(key=lambda x: x[0])

    print()
    if results:
        print(f"{'PORT':<10}{'DURUM':<10}{'SERVİS/BANNER'}")
        print("-" * 60)
        for port, service in results:
            print(f"{port:<10}{'AÇIK':<10}{service}")
    else:
        print("Açık port bulunamadı.")

    print()
    print(f"Tarama {elapsed:.2f} saniyede tamamlandı. {len(results)} açık port bulundu.")


if __name__ == "__main__":
    main()