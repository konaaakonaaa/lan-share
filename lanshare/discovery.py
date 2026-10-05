"""Обнаружение получателей в локальной сети.

Это собственный простой протокол поверх UDP (multicast + broadcast), а не
стандартный mDNS: стандартный mDNS без сторонней библиотеки реализовывать
слишком громоздко. Принцип тот же: получатель отвечает на запрос «кто тут?»
своим именем и TCP-портом.
"""
import json
import socket
import struct
import threading
import time

GROUP = "239.255.77.77"
PORT = 50505
QUERY = b"LANSHARE-DISCOVER/1"


class Advertiser(threading.Thread):
    """Слушает запросы поиска и отвечает на них."""

    def __init__(self, name, tcp_port, group=GROUP, port=PORT):
        super().__init__(daemon=True)
        self.name_ = name
        self.tcp_port = tcp_port
        self.group = group
        self.udp_port = port
        self._halt = threading.Event()
        self.sock = None
        self.error = None

    def start(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            s.bind(("", self.udp_port))
            try:
                mreq = struct.pack("4s4s", socket.inet_aton(self.group), socket.inet_aton("0.0.0.0"))
                s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except OSError:
                pass  # multicast недоступен, broadcast/unicast всё равно сработают
            s.settimeout(0.3)
            self.sock = s
        except OSError as e:
            self.error = e
            return
        super().start()

    def run(self):
        reply = json.dumps({"name": self.name_, "port": self.tcp_port, "v": 1}).encode()
        while not self._halt.is_set():
            try:
                data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            if data == QUERY:
                try:
                    self.sock.sendto(reply, addr)
                except OSError:
                    pass

    def stop(self):
        self._halt.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


def discover(timeout=2.0, targets=None):
    """Возвращает список {"name", "host", "port"} найденных получателей."""
    if targets is None:
        targets = [(GROUP, PORT), ("255.255.255.255", PORT)]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
    except OSError:
        pass

    def ask():
        for t in targets:
            try:
                s.sendto(QUERY, t)
            except OSError:
                pass

    found = {}
    deadline = time.monotonic() + timeout
    ask()
    resent = False
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        if not resent and left < timeout / 2:
            ask()
            resent = True
        s.settimeout(min(left, 0.2))
        try:
            data, addr = s.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            info = json.loads(data)
            key = (addr[0], int(info["port"]))
            found[key] = {"name": str(info["name"]), "host": addr[0], "port": key[1]}
        except (ValueError, KeyError, TypeError):
            continue
    s.close()
    return sorted(found.values(), key=lambda d: (d["name"].lower(), d["host"]))
