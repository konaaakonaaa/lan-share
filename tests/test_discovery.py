import socket
import unittest

from lanshare import discovery


def free_udp_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Discovery(unittest.TestCase):
    def test_unicast_query_finds_advertiser(self):
        port = free_udp_port()
        adv = discovery.Advertiser("Маша-ноутбук", 9123, port=port)
        adv.start()
        self.assertIsNone(adv.error)
        try:
            found = discovery.discover(1.0, targets=[("127.0.0.1", port)])
        finally:
            adv.stop()
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["name"], "Маша-ноутбук")
        self.assertEqual(found[0]["port"], 9123)
        self.assertEqual(found[0]["host"], "127.0.0.1")

    def test_nobody_found(self):
        self.assertEqual(discovery.discover(0.4, targets=[("127.0.0.1", free_udp_port())]), [])

    def test_ignores_garbage_replies(self):
        port = free_udp_port()
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", port)); srv.settimeout(1)
        import threading
        def junk():
            try:
                _, addr = srv.recvfrom(100)
                for payload in (b"\xff\xfe", b"{}", b'{"name":"x"}', b'{"name":"ok","port":5}'):
                    srv.sendto(payload, addr)
            except socket.timeout:
                pass
        t = threading.Thread(target=junk); t.start()
        found = discovery.discover(0.8, targets=[("127.0.0.1", port)])
        t.join(); srv.close()
        self.assertEqual([d["name"] for d in found], ["ok"])

    def test_multicast_if_environment_supports_it(self):
        port = free_udp_port()
        adv = discovery.Advertiser("mc-test", 7777, port=port)
        adv.start()
        try:
            found = discovery.discover(1.5, targets=[(discovery.GROUP, port)])
        finally:
            adv.stop()
        if not found:
            self.skipTest("в этом окружении multicast не доставляется (нет маршрута)")
        self.assertEqual(found[0]["name"], "mc-test")


if __name__ == "__main__":
    unittest.main()
