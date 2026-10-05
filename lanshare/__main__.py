import argparse
import getpass
import os
import sys
import threading

from . import __version__, discovery, transfer
from .crypto import AuthError, ProtocolError, normalize_code


def _parse():
    p = argparse.ArgumentParser(prog="lanshare", description="Передача файлов по локальной сети без сервера")
    p.add_argument("--version", action="version", version="lanshare " + __version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("receive", help="принимать файлы")
    r.add_argument("--port", type=int, default=9000)
    r.add_argument("--out", default=".", help="папка назначения (по умолчанию текущая)")
    r.add_argument("--name", help="имя в списке устройств (по умолчанию имя компьютера)")
    r.add_argument("--code", help="свой код сопряжения (по умолчанию случайный)")
    r.add_argument("--yes", action="store_true", help="принимать без вопроса")
    r.add_argument("--once", action="store_true", help="выйти после одной передачи")
    r.add_argument("--no-discovery", action="store_true", help="не отвечать на поиск в сети")

    sc = sub.add_parser("scan", help="найти получателей в сети")
    sc.add_argument("--timeout", type=float, default=2.0)

    s = sub.add_parser("send", help="отправить файлы или папки")
    s.add_argument("--to", action="append", default=[], metavar="HOST:PORT", help="адрес получателя (можно несколько раз)")
    s.add_argument("--name", action="append", default=[], metavar="ИМЯ", help="найти получателя по имени (можно несколько раз)")
    s.add_argument("--code", help="код сопряжения (если не указан, спросим)")
    s.add_argument("--timeout", type=float, default=2.0, help="сколько искать по имени, секунд")
    s.add_argument("paths", nargs="+", metavar="ПУТЬ")
    return p


def _cmd_receive(a):
    rx = transfer.Receiver(out_dir=a.out, name=a.name, port=a.port, code=a.code,
                           auto_accept=a.yes, once=a.once, advertise=not a.no_discovery)
    rx.listen()
    rx.serve_forever()
    return 0


def _cmd_scan(a):
    found = discovery.discover(a.timeout)
    if not found:
        print("Никого не найдено. Проверьте, что получатель запущен в той же сети "
              "и что файрвол пропускает UDP 50505 (или используйте --to host:port).")
        return 1
    for d in found:
        print("%-24s %s:%d" % (d["name"], d["host"], d["port"]))
    return 0


def _cmd_send(a):
    targets = []   # (подпись, "host:port")
    for t in a.to:
        targets.append((t, t))
    if a.name:
        found = discovery.discover(a.timeout)
        for wanted in a.name:
            hits = [d for d in found if d["name"].lower() == wanted.lower()]
            if not hits:
                print("Получатель «%s» не найден в сети. Что видно: %s" % (
                    wanted, ", ".join(d["name"] for d in found) or "ничего"), file=sys.stderr)
                return 1
            for d in hits:
                targets.append((d["name"], "%s:%d" % (d["host"], d["port"])))
    if not targets:
        print("Укажите получателя: --to HOST:PORT или --name ИМЯ", file=sys.stderr)
        return 2

    codes = []
    for label, _ in targets:
        c = a.code or getpass.getpass("Код сопряжения для %s: " % label)
        codes.append(normalize_code(c))

    multi = len(targets) > 1
    errors = []
    lock = threading.Lock()

    def run(label, addr, code):
        tag = "[%s] " % label if multi else ""
        try:
            transfer.send(addr, a.paths, code, quiet=multi, tag=tag)
            with lock:
                print("%sГотово: всё доставлено и проверено" % tag)
        except (AuthError, transfer.Declined, ProtocolError, OSError, ValueError) as e:
            with lock:
                print("%sОшибка: %s" % (tag, e), file=sys.stderr)
                errors.append(label)

    if multi:
        ts = [threading.Thread(target=run, args=(l, ad, c)) for (l, ad), c in zip(targets, codes)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
    else:
        run(targets[0][0], targets[0][1], codes[0])
    return 1 if errors else 0


def main(argv=None):
    a = _parse().parse_args(argv)
    try:
        return {"receive": _cmd_receive, "scan": _cmd_scan, "send": _cmd_send}[a.cmd](a)
    except KeyboardInterrupt:
        print("\nПрервано.", file=sys.stderr)
        return 130
    except OSError as e:
        print("Ошибка:", e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
