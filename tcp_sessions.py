#!/usr/bin/env python3
"""
TCP Session Analyzer
Показывает активные TCP-соединения на текущей машине с именем процесса,
состоянием сессии, трафиком и опциональным DNS-резолвом.

Требования:
    pip install psutil

Запуск:
    python tcp_sessions.py               # все соединения
    python tcp_sessions.py -s ESTABLISHED  # только установленные
    python tcp_sessions.py -p 443          # только порт 443
    python tcp_sessions.py -r              # с резолвом hostname
    python tcp_sessions.py --watch         # обновление каждые 2 сек
"""

import argparse
import os
import platform
import socket
import sys
import time
from collections import Counter
from datetime import datetime

try:
    import psutil
except ImportError:
    print("[!] Установи psutil: pip install psutil")
    sys.exit(1)

# ─── Константы ────────────────────────────────────────────────────────────────

# Все возможные состояния TCP-сессии (RFC 793 + OS-специфичные)
TCP_STATES = {
    "ESTABLISHED"  : "Активное соединение, данные передаются",
    "LISTEN"       : "Ожидание входящих соединений (сервер)",
    "TIME_WAIT"    : "Ожидание завершения (после FIN)",
    "CLOSE_WAIT"   : "Удалённая сторона закрыла соединение",
    "SYN_SENT"     : "Отправлен SYN, ожидание SYN-ACK",
    "SYN_RECV"     : "Получен SYN, отправлен SYN-ACK",
    "FIN_WAIT1"    : "Инициировано закрытие, отправлен FIN",
    "FIN_WAIT2"    : "FIN подтверждён, ожидание FIN от удалённой стороны",
    "LAST_ACK"     : "Ожидание ACK на последний FIN",
    "CLOSING"      : "Обе стороны закрывают одновременно",
    "NONE"         : "Нет состояния",
    "DELETE_TCB"   : "Соединение удаляется (Windows)",
}

# Цвета для терминала
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# Windows не поддерживает ANSI по умолчанию — отключаем цвета
USE_COLOR = platform.system() != "Windows" or os.environ.get("TERM")

def c(color: str, text: str) -> str:
    return f"{color}{text}{RESET}" if USE_COLOR else text


# ─── Работа с соединениями ────────────────────────────────────────────────────

def get_process_name(pid: int | None) -> str:
    """Получить имя процесса по PID."""
    if pid is None:
        return "—"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"pid:{pid}"


_dns_cache: dict[str, str] = {}

def resolve(ip: str) -> str:
    """Обратный DNS-резолв с кешированием."""
    if not ip or ip in ("0.0.0.0", "::"):
        return ""
    if ip in _dns_cache:
        return _dns_cache[ip]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        name = ip
    _dns_cache[ip] = name
    return name


def state_color(state: str) -> str:
    """Подкрасить состояние по смыслу."""
    if state == "ESTABLISHED":
        return c(GREEN, state)
    if state == "LISTEN":
        return c(CYAN, state)
    if state in ("TIME_WAIT", "CLOSE_WAIT", "FIN_WAIT1", "FIN_WAIT2"):
        return c(YELLOW, state)
    if state in ("SYN_SENT", "SYN_RECV"):
        return c(YELLOW, state)
    return c(GRAY, state)


def get_connections(
    filter_state: str | None = None,
    filter_port:  int | None = None,
    do_resolve:   bool       = False,
) -> list[dict]:
    """
    Собрать все TCP-соединения через psutil.
    Возвращает список dict с полями для отображения.
    """
    try:
        raw = psutil.net_connections(kind="tcp")
    except psutil.AccessDenied:
        print("[!] Недостаточно прав. Запусти с sudo / от Администратора.")
        sys.exit(1)

    rows = []
    for conn in raw:
        state = conn.status or "NONE"

        # Фильтр по состоянию
        if filter_state and state != filter_state.upper():
            continue

        laddr = conn.laddr
        raddr = conn.raddr

        local_ip   = laddr.ip   if laddr else ""
        local_port = laddr.port if laddr else 0
        remote_ip  = raddr.ip   if raddr else ""
        remote_port = raddr.port if raddr else 0

        # Фильтр по порту (локальный ИЛИ удалённый)
        if filter_port is not None:
            if local_port != filter_port and remote_port != filter_port:
                continue

        remote_host = resolve(remote_ip) if (do_resolve and remote_ip) else remote_ip

        rows.append({
            "pid"         : conn.pid,
            "process"     : get_process_name(conn.pid),
            "state"       : state,
            "local_ip"    : local_ip,
            "local_port"  : local_port,
            "remote_ip"   : remote_ip,
            "remote_port" : remote_port,
            "remote_host" : remote_host,
        })

    # Сортировка: сначала ESTABLISHED, потом LISTEN, потом остальные
    order = {"ESTABLISHED": 0, "LISTEN": 1}
    rows.sort(key=lambda r: (order.get(r["state"], 2), r["process"]))
    return rows


# ─── Отображение ──────────────────────────────────────────────────────────────

def fmt_addr(ip: str, port: int) -> str:
    if not ip:
        return "—"
    return f"{ip}:{port}"


def print_table(rows: list[dict]) -> None:
    """Вывести таблицу соединений."""
    if not rows:
        print(c(YELLOW, "  Соединений не найдено."))
        return

    # Ширина колонок
    w_proc  = max(len(r["process"]) for r in rows)
    w_proc  = max(w_proc, 12)
    w_state = 13
    w_local = max(len(fmt_addr(r["local_ip"], r["local_port"])) for r in rows)
    w_local = max(w_local, 21)
    w_remote = max(
        len(r["remote_host"] or fmt_addr(r["remote_ip"], r["remote_port"]))
        for r in rows
    )
    w_remote = max(w_remote, 25)

    header = (
        f"  {c(BOLD,'PROCESS'):<{w_proc+9}}  "
        f"{c(BOLD,'STATE'):<{w_state+9}}  "
        f"{c(BOLD,'LOCAL ADDRESS'):<{w_local}}  "
        f"{c(BOLD,'REMOTE ADDRESS'):<{w_remote}}  "
        f"{c(BOLD,'PID')}"
    )
    sep = f"  {'-'*w_proc}  {'-'*w_state}  {'-'*w_local}  {'-'*w_remote}  {'-'*6}"

    print(header)
    print(sep)

    for r in rows:
        local  = fmt_addr(r["local_ip"], r["local_port"])
        remote = r["remote_host"] if r["remote_host"] else fmt_addr(r["remote_ip"], r["remote_port"])
        if not r["remote_ip"]:
            remote = "—"

        pid_str = str(r["pid"]) if r["pid"] else "—"

        print(
            f"  {r['process']:<{w_proc}}  "
            f"{state_color(r['state']):<{w_state + (18 if USE_COLOR else 0)}}  "
            f"{local:<{w_local}}  "
            f"{remote:<{w_remote}}  "
            f"{pid_str}"
        )


def print_summary(rows: list[dict]) -> None:
    """Вывести статистику по состояниям и процессам."""
    state_counts   = Counter(r["state"]   for r in rows)
    process_counts = Counter(r["process"] for r in rows)

    print(f"\n  {c(BOLD, 'Состояния:')}")
    for state, count in state_counts.most_common():
        desc = TCP_STATES.get(state, "")
        bar  = "█" * count
        print(f"    {state_color(state):<30}  {count:>3}  {c(GRAY, bar[:30])}")
        if desc:
            print(f"    {c(GRAY, desc)}")

    print(f"\n  {c(BOLD, 'Топ процессов:')}")
    for proc, count in process_counts.most_common(10):
        print(f"    {proc:<25}  {count} соед.")


def clear_screen() -> None:
    os.system("cls" if platform.system() == "Windows" else "clear")


# ─── Точка входа ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="TCP Session Analyzer — активные TCP-соединения на этом хосте"
    )
    parser.add_argument(
        "-s", "--state",
        metavar="STATE",
        help="Фильтр по состоянию: ESTABLISHED, LISTEN, TIME_WAIT и т.д."
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        metavar="PORT",
        help="Фильтр по порту (локальный или удалённый)"
    )
    parser.add_argument(
        "-r", "--resolve",
        action="store_true",
        help="Резолвить IP в hostname через обратный DNS"
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Показать статистику по состояниям и процессам"
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Обновлять таблицу каждые 2 секунды (как top)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Интервал обновления для --watch (по умолчанию: 2 сек)"
    )
    args = parser.parse_args()

    def run_once() -> None:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = get_connections(
            filter_state=args.state,
            filter_port=args.port,
            do_resolve=args.resolve,
        )
        print(f"\n  {c(BOLD, 'TCP Session Analyzer')}  {c(GRAY, now)}")
        print(f"  OS: {platform.system()} {platform.release()}  |  "
              f"Соединений: {c(BOLD, str(len(rows)))}\n")
        print_table(rows)
        if args.summary:
            print_summary(rows)
        print()

    if args.watch:
        try:
            while True:
                clear_screen()
                run_once()
                print(c(GRAY, f"  Обновление каждые {args.interval} сек. Ctrl+C для выхода."))
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n  Выход.")
    else:
        run_once()


if __name__ == "__main__":
    main()
