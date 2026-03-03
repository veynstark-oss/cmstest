#!/usr/bin/env python3
"""
HashCrack — distributed hashcat orchestrator for Vast.ai

Usage:
  python hashcrack.py run   -H hashes.txt -w wordlist.txt -r rules.rule [-o cracked.txt] [-m 1710]
  python hashcrack.py status
  python hashcrack.py collect [-o cracked.txt]
  python hashcrack.py instances
  python hashcrack.py reset

  python hashcrack.py search [-g "RTX 4090"] [-n 4] [-c 5.0]
  python hashcrack.py rent <offer_id> [--wait]
  python hashcrack.py destroy <instance_id>
  python hashcrack.py destroy-all [-f]

  python hashcrack.py deploy archive.zip [-i id1,id2]
  python hashcrack.py deploy --url https://example.com/file.zip

  python hashcrack.py ssh [instance_id]
  python hashcrack.py exec "nvidia-smi"
  python hashcrack.py logs [instance_id] [-f]
  python hashcrack.py cost
  python hashcrack.py ssh-setup

Commands:
  run          — Разбить хэши, раздать по инстансам, запустить hashcat, мониторить
  status       — Показать текущий статус (без запуска)
  collect      — Принудительно забрать cracked.txt со всех инстансов
  instances    — Показать запущенные инстансы на Vast.ai
  reset        — Очистить состояние (для нового запуска)
  search       — Поиск GPU на маркетплейсе
  rent         — Арендовать инстанс. --wait ждёт запуска
  destroy      — Уничтожить один инстанс
  destroy-all  — Уничтожить все инстансы
  deploy       — Загрузить (или скачать по URL) и распаковать архив на инстансы
  ssh          — Быстрое SSH подключение к инстансу
  exec         — Выполнить команду на всех инстансах параллельно
  logs         — Просмотр hashcat логов с инстанса (-f для follow)
  cost         — Расходы: баланс, burn rate, время до нуля
  ssh-setup    — Генерация SSH ключа и настройка Vast.ai
"""

import argparse
import sys

from rich.console import Console
from rich.table import Table

console = Console()


def cmd_run(args):
    from lib.orchestrator import Orchestrator

    instance_ids = None
    if args.instances:
        instance_ids = [int(x.strip()) for x in args.instances.split(",")]

    orch = Orchestrator(
        hash_file=args.hashes,
        wordlist=args.wordlist,
        rules=args.rules,
        output_file=args.output,
        mode=args.mode,
        instance_ids=instance_ids,
    )
    try:
        orch.run()
    finally:
        orch.cleanup()


def cmd_status(args):
    from lib.orchestrator import Orchestrator

    orch = Orchestrator(hash_file="", wordlist="", rules="")
    orch.status()


def cmd_collect(args):
    from lib.orchestrator import Orchestrator

    orch = Orchestrator(
        hash_file="", wordlist="", rules="",
        output_file=args.output,
    )
    orch.collect()
    orch.cleanup()


def cmd_instances(args):
    from lib.vastai import vastai

    console.print("[cyan]🔍 Запрос инстансов Vast.ai...[/]")
    try:
        instances = vastai.get_instances()
    except Exception as e:
        console.print(f"[red]✗ Ошибка API: {e}[/]")
        return

    if not instances:
        console.print("[yellow]Нет инстансов.[/]")
        return

    table = Table(title="Vast.ai Instances", border_style="dim")
    table.add_column("ID", style="dim")
    table.add_column("GPU", style="cyan")
    table.add_column("×", justify="right")
    table.add_column("Status", width=10)
    table.add_column("SSH", width=28)
    table.add_column("$/hr", justify="right")

    for i in instances:
        status = i.get("actual_status", "?")
        style = "green" if status == "running" else "yellow" if status == "loading" else "red"
        ssh = f"{i.get('ssh_host', '')}:{i.get('ssh_port', '')}" if i.get("ssh_host") else "—"
        table.add_row(
            str(i.get("id", "?")),
            i.get("gpu_name", "?"),
            str(i.get("num_gpus", "?")),
            f"[{style}]{status}[/]",
            ssh,
            f"${i.get('dph_total', 0):.2f}",
        )

    console.print(table)


def cmd_reset(args):
    from lib.state import clear_state, STATE_DIR
    import shutil

    if not args.force:
        console.print("[yellow]⚠  Это удалит состояние задания и все чанки.[/]")
        resp = input("Продолжить? [y/N] ").strip().lower()
        if resp != "y":
            console.print("[dim]Отменено.[/]")
            return

    clear_state()
    chunks_dir = STATE_DIR / "chunks"
    results_dir = STATE_DIR / "results"
    if chunks_dir.exists():
        shutil.rmtree(chunks_dir)
    if results_dir.exists():
        shutil.rmtree(results_dir)
    console.print("[green]✓ Состояние очищено.[/]")


def cmd_search(args):
    from lib.vastai import vastai

    cost_str = f"${args.min_cost:.2f}–${args.max_cost:.2f}/hr" if args.min_cost > 0 else f"до ${args.max_cost:.2f}/hr"
    console.print(f"[cyan]🔍 Поиск GPU: {args.gpu or 'любая'}, ×{args.num_gpus}, {cost_str}...[/]")
    try:
        offers = vastai.search_offers(
            gpu_name=args.gpu,
            num_gpus=args.num_gpus,
            min_dph=args.min_cost,
            max_dph=args.max_cost,
            min_gpu_ram_gb=args.min_ram,
            limit=args.limit,
        )
    except Exception as e:
        console.print(f"[red]✗ Ошибка API: {e}[/]")
        return

    if not offers:
        console.print("[yellow]Ничего не найдено. Попробуйте увеличить --max-cost или уменьшить --num-gpus.[/]")
        return

    table = Table(title=f"Доступные GPU ({len(offers)} офферов)", border_style="dim")
    table.add_column("Offer ID", style="dim")
    table.add_column("GPU", style="cyan")
    table.add_column("×", justify="right")
    table.add_column("VRAM", justify="right")
    table.add_column("CPU", justify="right")
    table.add_column("RAM", justify="right")
    table.add_column("Disk", justify="right")
    table.add_column("DL Mbps", justify="right")
    table.add_column("$/hr", justify="right", style="green")

    for o in offers:
        gpu_ram_gb = round(o.get("gpu_ram", 0) / 1024, 1)
        ram_gb = round(o.get("cpu_ram", 0) / 1024, 1)
        table.add_row(
            str(o.get("id", "?")),
            o.get("gpu_name", "?"),
            str(o.get("num_gpus", "?")),
            f"{gpu_ram_gb}G",
            str(o.get("cpu_cores_effective", "?")),
            f"{ram_gb}G",
            f"{o.get('disk_space', 0):.0f}G",
            f"{o.get('inet_down', 0):.0f}",
            f"${o.get('dph_total', 0):.2f}",
        )

    console.print(table)
    console.print(f"\n[dim]Арендовать: python hashcrack.py rent <Offer ID>[/]")


def cmd_rent(args):
    from lib.vastai import vastai

    offer_id = args.offer_id
    console.print(f"[yellow]💰 Аренда оффера {offer_id}...[/]")

    try:
        result = vastai.rent_instance(
            offer_id=offer_id,
            image=args.image,
            disk_gb=args.disk,
        )
    except Exception as e:
        console.print(f"[red]✗ Ошибка аренды: {e}[/]")
        return

    new_id = result.get("new_contract")
    if new_id:
        console.print(f"[green]✓ Инстанс создан! ID: {new_id}[/]")

        if args.wait:
            import time
            console.print("[yellow]⏳ Ожидание запуска инстанса...[/]")
            for attempt in range(60):  # max 5 min
                time.sleep(5)
                try:
                    inst = vastai.get_instance(new_id)
                    status = inst.get("actual_status", "?")
                    if status == "running":
                        ssh_info = f"{inst.get('ssh_host')}:{inst.get('ssh_port')}" if inst.get('ssh_host') else ""
                        console.print(f"[green]✓ Инстанс {new_id} запущен! SSH: {ssh_info}[/]")
                        return
                    elif status in ("exited", "error"):
                        console.print(f"[red]✗ Инстанс {new_id} завершился с ошибкой: {status}[/]")
                        return
                    else:
                        if attempt % 6 == 0:  # каждые 30 сек
                            console.print(f"  [dim]статус: {status}... ({(attempt + 1) * 5}s)[/]")
                except Exception:
                    pass
            console.print(f"[yellow]⚠  Таймаут. Проверьте: python hashcrack.py instances[/]")
        else:
            console.print(f"[dim]  Подождите 1-3 минуты пока загрузится, затем:[/]")
            console.print(f"[dim]  python hashcrack.py instances[/]")
    else:
        console.print(f"[yellow]Ответ API: {result}[/]")


def cmd_destroy(args):
    from lib.vastai import vastai

    instance_id = args.instance_id

    if not args.force:
        console.print(f"[yellow]⚠  Уничтожить инстанс {instance_id}?[/]")
        resp = input("Продолжить? [y/N] ").strip().lower()
        if resp != "y":
            console.print("[dim]Отменено.[/]")
            return

    try:
        vastai.destroy_instance(instance_id)
        console.print(f"[green]✓ Инстанс {instance_id} уничтожен.[/]")
    except Exception as e:
        console.print(f"[red]✗ Ошибка: {e}[/]")


def cmd_deploy(args):
    import os
    import threading
    from lib.vastai import vastai
    from lib.ssh import SSHManager
    from lib.config import REMOTE_WORK_DIR

    url_mode = bool(args.url)
    if not url_mode and not args.archive:
        console.print("[red]✗ Укажите путь к архиву или --url[/]")
        console.print("[dim]  python hashcrack.py deploy archive.zip[/]")
        console.print("[dim]  python hashcrack.py deploy --url https://example.com/file.zip[/]")
        return
    if url_mode:
        url = args.url
        name = url.split("/")[-1].split("?")[0] or "archive"
        console.print(f"[cyan]🌐 URL: {url}[/]")
        console.print(f"[cyan]📦 Файл: {name}[/]")
    else:
        archive = os.path.abspath(args.archive)
        if not os.path.isfile(archive):
            console.print(f"[red]✗ Файл не найден: {archive}[/]")
            return
        size_mb = os.path.getsize(archive) / 1024 / 1024
        name = os.path.basename(archive)
        console.print(f"[cyan]📦 Архив: {name} ({size_mb:.1f} MB)[/]")

    # Get instances
    console.print("[cyan]🔍 Получаем running инстансы...[/]")
    try:
        instances = vastai.get_running_instances()
    except Exception as e:
        console.print(f"[red]✗ Ошибка API: {e}[/]")
        return

    if args.instances:
        ids = [int(x.strip()) for x in args.instances.split(",")]
        instances = [i for i in instances if i.get("id") in ids]

    if not instances:
        console.print("[red]✗ Нет running инстансов.[/]")
        return

    console.print(f"[green]✓ Целевые инстансы: {len(instances)}[/]")

    # Determine unpack command
    name_lower = name.lower()
    if name_lower.endswith(".tar.gz") or name_lower.endswith(".tgz"):
        unpack_cmd = "tar xzf"
    elif name_lower.endswith(".tar.bz2"):
        unpack_cmd = "tar xjf"
    elif name_lower.endswith(".tar.xz"):
        unpack_cmd = "tar xJf"
    elif name_lower.endswith(".tar"):
        unpack_cmd = "tar xf"
    elif name_lower.endswith(".zip"):
        unpack_cmd = "unzip -o"
    elif name_lower.endswith(".7z"):
        unpack_cmd = "7z x -y"
    else:
        console.print("[red]✗ Неподдерживаемый формат. Поддержка: .zip, .tar.gz, .tgz, .tar.bz2, .tar.xz, .tar, .7z[/]")
        return

    remote_archive = f"{REMOTE_WORK_DIR}/{name}"
    target_dir = args.dir or REMOTE_WORK_DIR

    results = {}
    lock = threading.Lock()

    def deploy_one(inst):
        iid = inst["id"]
        host = inst.get("ssh_host", "")
        port = inst.get("ssh_port", 22)
        label = f"{host}:{port}"
        ssh = SSHManager(host, port)
        try:
            ssh.connect()
            with lock:
                console.print(f"  [{iid}] ✓ Подключен к {label}")

            # Install unzip/7z if needed
            if "unzip" in unpack_cmd:
                ssh.run("which unzip >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq unzip)", timeout=60)
            if "7z" in unpack_cmd:
                ssh.run("which 7z >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq p7zip-full)", timeout=60)

            # Create dir
            ssh.run(f"mkdir -p {target_dir}", timeout=10)

            # Upload or wget
            if url_mode:
                with lock:
                    console.print(f"  [{iid}] 🌐 Скачивание по URL...")
                ssh.run("which wget >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq wget)", timeout=60)
                code, out, err = ssh.run(f"wget -q --show-progress -O {remote_archive} '{url}'", timeout=600)
                if code != 0:
                    with lock:
                        console.print(f"  [{iid}] [red]✗ Ошибка wget: {err[:200]}[/]")
                    results[iid] = False
                    return
                with lock:
                    console.print(f"  [{iid}] ✓ Скачано")
            else:
                with lock:
                    console.print(f"  [{iid}] 📤 Загрузка {size_mb:.1f} MB...")
                ssh.upload_file(archive, remote_archive)
                with lock:
                    console.print(f"  [{iid}] ✓ Загружено")

            # Extract
            with lock:
                console.print(f"  [{iid}] 📦 Распаковка...")
            code, out, err = ssh.run(f"cd {target_dir} && {unpack_cmd} {remote_archive}", timeout=300)
            if code != 0:
                with lock:
                    console.print(f"  [{iid}] [red]✗ Ошибка распаковки: {err[:200]}[/]")
                results[iid] = False
                return

            # Remove archive to save disk
            ssh.run(f"rm -f {remote_archive}", timeout=10)

            # List extracted files
            _, listing, _ = ssh.run(f"find {target_dir} -maxdepth 2 -type f | head -20", timeout=10)
            file_count_str, _, _ = ssh.run(f"find {target_dir} -type f | wc -l", timeout=10)
            file_count = file_count_str.strip()

            with lock:
                console.print(f"  [{iid}] [green]✓ Готово! {file_count} файлов в {target_dir}[/]")
                if listing.strip():
                    for line in listing.strip().split("\n")[:5]:
                        console.print(f"  [{iid}]   [dim]{line}[/]")
                    try:
                        if int(file_count) > 5:
                            console.print(f"  [{iid}]   [dim]...[/]")
                    except ValueError:
                        pass

            results[iid] = True
        except Exception as e:
            with lock:
                console.print(f"  [{iid}] [red]✗ Ошибка: {e}[/]")
            results[iid] = False
        finally:
            ssh.close()

    threads = []
    for inst in instances:
        t = threading.Thread(target=deploy_one, args=(inst,), daemon=True)
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=600)

    ok = sum(1 for v in results.values() if v)
    fail = sum(1 for v in results.values() if not v)
    console.print(f"\n[bold green]✓ Распаковано: {ok}[/] | [bold red]Ошибок: {fail}[/]")


# ── ssh-setup ──────────────────────────────────────────────────────────────

def cmd_ssh_setup(args):
    """Generate SSH key and register it in Vast.ai account."""
    import os
    import subprocess
    from lib.vastai import vastai

    home = os.path.expanduser("~")
    key_path = os.path.join(home, ".ssh", "id_ed25519")
    pub_path = key_path + ".pub"

    # Generate key if not exists
    if not os.path.isfile(key_path):
        console.print("[yellow]🔑 Генерация SSH ключа (ed25519)...[/]")
        os.makedirs(os.path.dirname(key_path), exist_ok=True)
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""],
            check=True, capture_output=True,
        )
        console.print(f"[green]✓ Ключ создан: {key_path}[/]")
    else:
        console.print(f"[green]✓ Ключ существует: {key_path}[/]")

    with open(pub_path) as f:
        pub_key = f.read().strip()

    console.print(f"[dim]  {pub_key[:70]}...[/]")

    # Check current key in Vast.ai
    console.print("[cyan]🔍 Проверяем SSH ключ в аккаунте Vast.ai...[/]")
    try:
        user = vastai.whoami()
    except Exception as e:
        console.print(f"[red]✗ Ошибка API: {e}[/]")
        return

    existing = user.get("ssh_key", "") or ""
    pub_fingerprint = pub_key.split()[1] if len(pub_key.split()) > 1 else pub_key

    if pub_fingerprint in existing:
        console.print("[green]✓ Ключ уже зарегистрирован в Vast.ai![/]")
        return

    # Try to update via API
    console.print("[yellow]📤 Добавляем ключ в Vast.ai...[/]")
    combined = existing.rstrip() + "\n" + pub_key if existing.strip() else pub_key

    try:
        import httpx
        r = httpx.put(
            f"{vastai.base}/users/current/?api_key={vastai.api_key}",
            json={"ssh_key": combined},
            timeout=15,
        )
        if r.status_code == 200:
            console.print("[green]✓ SSH ключ добавлен в Vast.ai![/]")
            console.print("[dim]  Пересоздайте инстансы чтобы ключ применился.[/]")
            return
    except Exception:
        pass

    # If API fails — manual instructions
    console.print("[yellow]⚠  API не позволяет обновить ключ автоматически.[/]")
    console.print("[yellow]   Добавьте ключ вручную на https://cloud.vast.ai/account/[/]")
    console.print(f"\n[bold white]{pub_key}[/]\n")
    console.print("[dim]После добавления пересоздайте инстансы (destroy + rent).[/]")


# ── exec ───────────────────────────────────────────────────────────────────

def cmd_exec(args):
    """Execute a command on all (or selected) running instances in parallel."""
    import threading
    from lib.vastai import vastai
    from lib.ssh import SSHManager

    command = args.cmd
    console.print(f"[cyan]⚡ Команда: {command}[/]")

    try:
        instances = vastai.get_running_instances()
    except Exception as e:
        console.print(f"[red]✗ Ошибка API: {e}[/]")
        return

    if args.instances:
        ids = [int(x.strip()) for x in args.instances.split(",")]
        instances = [i for i in instances if i.get("id") in ids]

    if not instances:
        console.print("[red]✗ Нет running инстансов.[/]")
        return

    console.print(f"[green]✓ Инстансы: {len(instances)}[/]\n")

    lock = threading.Lock()
    timeout = args.timeout or 30

    def run_on(inst):
        iid = inst["id"]
        host = inst.get("ssh_host", "")
        port = inst.get("ssh_port", 22)
        ssh = SSHManager(host, port)
        try:
            ssh.connect()
            code, out, err = ssh.run(command, timeout=timeout)
            with lock:
                status = "[green]OK[/]" if code == 0 else f"[red]exit {code}[/]"
                console.print(f"[bold]── [{iid}] {host}:{port} ── {status}[/]")
                if out.strip():
                    console.print(out.rstrip())
                if err.strip():
                    console.print(f"[red]{err.rstrip()}[/]")
                console.print()
        except Exception as e:
            with lock:
                console.print(f"[bold]── [{iid}] ── [red]✗ {e}[/]\n")
        finally:
            ssh.close()

    threads = [threading.Thread(target=run_on, args=(i,), daemon=True) for i in instances]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 30)


# ── cost ───────────────────────────────────────────────────────────────────

def cmd_cost(args):
    """Show current spending: balance, burn rate, running costs."""
    from lib.vastai import vastai

    console.print("[cyan]💰 Расходы Vast.ai...[/]\n")

    try:
        user = vastai.whoami()
        instances = vastai.get_instances()
    except Exception as e:
        console.print(f"[red]✗ Ошибка API: {e}[/]")
        return

    credit = user.get("credit", 0)
    console.print(f"  Баланс:        [bold green]${credit:.2f}[/]")

    running = [i for i in instances if i.get("actual_status") == "running"]
    total_dph = sum(i.get("dph_total", 0) for i in running)
    total_gpus = sum(i.get("num_gpus", 0) for i in running)

    console.print(f"  Инстансы:      [cyan]{len(running)}[/] running ({total_gpus} GPU)")
    console.print(f"  Burn rate:     [yellow]${total_dph:.2f}/hr[/]  (${total_dph * 24:.2f}/day)")

    if total_dph > 0:
        hours_left = credit / total_dph
        console.print(f"  Хватит на:     [{'red' if hours_left < 2 else 'yellow' if hours_left < 12 else 'green'}]{hours_left:.1f} часов ({hours_left / 24:.1f} дней)[/]")
    else:
        console.print(f"  Хватит на:     [green]∞ (нет running инстансов)[/]")

    if running:
        console.print()
        table = Table(border_style="dim")
        table.add_column("ID", style="dim")
        table.add_column("GPU", style="cyan")
        table.add_column("×")
        table.add_column("$/hr", justify="right", style="yellow")
        table.add_column("$/day", justify="right")
        table.add_column("Uptime", justify="right")

        import time
        for i in running:
            started = i.get("start_date", 0)
            if started:
                uptime_s = time.time() - started
                uptime = f"{int(uptime_s // 3600)}h {int(uptime_s % 3600 // 60)}m"
                cost_so_far = i.get("dph_total", 0) * uptime_s / 3600
            else:
                uptime = "?"
                cost_so_far = 0

            table.add_row(
                str(i.get("id")),
                i.get("gpu_name", "?"),
                str(i.get("num_gpus", "?")),
                f"${i.get('dph_total', 0):.2f}",
                f"${i.get('dph_total', 0) * 24:.2f}",
                uptime,
            )

        console.print(table)


# ── destroy-all ────────────────────────────────────────────────────────────

def cmd_destroy_all(args):
    """Destroy all running instances."""
    from lib.vastai import vastai

    try:
        instances = vastai.get_instances()
    except Exception as e:
        console.print(f"[red]✗ Ошибка API: {e}[/]")
        return

    if not instances:
        console.print("[yellow]Нет инстансов.[/]")
        return

    console.print(f"[yellow]⚠  Будут уничтожены {len(instances)} инстансов:[/]")
    for i in instances:
        console.print(f"  • [{i.get('id')}] {i.get('gpu_name', '?')} ×{i.get('num_gpus', '?')} — {i.get('actual_status', '?')}")

    if not args.force:
        resp = input("\nПродолжить? [y/N] ").strip().lower()
        if resp != "y":
            console.print("[dim]Отменено.[/]")
            return

    ok = 0
    for i in instances:
        try:
            vastai.destroy_instance(i["id"])
            console.print(f"  [green]✓ {i['id']} уничтожен[/]")
            ok += 1
        except Exception as e:
            console.print(f"  [red]✗ {i['id']}: {e}[/]")

    console.print(f"\n[bold green]✓ Уничтожено: {ok}/{len(instances)}[/]")


# ── logs ───────────────────────────────────────────────────────────────────

def cmd_logs(args):
    """Show hashcat logs from an instance."""
    from lib.vastai import vastai
    from lib.ssh import SSHManager
    from lib.config import REMOTE_WORK_DIR

    try:
        instances = vastai.get_running_instances()
    except Exception as e:
        console.print(f"[red]✗ Ошибка API: {e}[/]")
        return

    # Pick instance
    if args.instance_id:
        inst = next((i for i in instances if i.get("id") == args.instance_id), None)
        if not inst:
            console.print(f"[red]✗ Инстанс {args.instance_id} не найден или не running.[/]")
            return
    elif len(instances) == 1:
        inst = instances[0]
    else:
        console.print("[yellow]Укажите ID инстанса (--instance-id) или используйте:[/]")
        for i in instances:
            console.print(f"  python hashcrack.py logs {i['id']}")
        return

    ssh = SSHManager(inst["ssh_host"], inst["ssh_port"])
    try:
        ssh.connect()
        lines = args.lines or 50
        if args.follow:
            console.print(f"[dim]Логи с [{inst['id']}] (Ctrl+C для выхода)...[/]\n")
            import subprocess
            subprocess.run([
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-p", str(inst["ssh_port"]),
                f"root@{inst['ssh_host']}",
                f"tail -f {REMOTE_WORK_DIR}/hashcat_out.log"
            ])
        else:
            _, out, _ = ssh.run(f"tail -n {lines} {REMOTE_WORK_DIR}/hashcat_out.log 2>/dev/null", timeout=10)
            if out.strip():
                console.print(f"[dim]── [{inst['id']}] последние {lines} строк ──[/]")
                console.print(out.rstrip())
            else:
                console.print(f"[yellow]Лог пуст или не найден на [{inst['id']}].[/]")
    except Exception as e:
        console.print(f"[red]✗ Ошибка: {e}[/]")
    finally:
        ssh.close()


# ── ssh (quick connect) ───────────────────────────────────────────────────

def cmd_ssh(args):
    """Open an interactive SSH session to an instance."""
    import subprocess
    from lib.vastai import vastai

    try:
        instances = vastai.get_running_instances()
    except Exception as e:
        console.print(f"[red]✗ Ошибка API: {e}[/]")
        return

    if args.instance_id:
        inst = next((i for i in instances if i.get("id") == args.instance_id), None)
        if not inst:
            console.print(f"[red]✗ Инстанс {args.instance_id} не найден или не running.[/]")
            return
    elif len(instances) == 1:
        inst = instances[0]
    else:
        console.print("[yellow]Выберите инстанс:[/]")
        for i in instances:
            console.print(f"  python hashcrack.py ssh {i['id']}  # {i.get('gpu_name','?')} ×{i.get('num_gpus','?')}")
        return

    host = inst["ssh_host"]
    port = inst["ssh_port"]
    console.print(f"[cyan]🔗 Подключение к [{inst['id']}] {host}:{port}...[/]")

    subprocess.run([
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-p", str(port),
        f"root@{host}",
    ])


def main():
    parser = argparse.ArgumentParser(
        prog="hashcrack",
        description="Distributed hashcat orchestrator for Vast.ai",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # run
    p_run = sub.add_parser("run", help="Запустить распределённый hashcat")
    p_run.add_argument("-H", "--hashes", required=True, help="Файл с хэшами")
    p_run.add_argument("-w", "--wordlist", required=True, help="Wordlist файл")
    p_run.add_argument("-r", "--rules", required=True, help="Rules файл")
    p_run.add_argument("-o", "--output", default="cracked.txt", help="Выходной файл (default: cracked.txt)")
    p_run.add_argument("-m", "--mode", type=int, default=1710, help="Hashcat mode (default: 1710)")
    p_run.add_argument("-i", "--instances", default=None, help="ID инстансов через запятую (по умолчанию: все running)")
    p_run.set_defaults(func=cmd_run)

    # status
    p_status = sub.add_parser("status", help="Показать статус")
    p_status.set_defaults(func=cmd_status)

    # collect
    p_collect = sub.add_parser("collect", help="Забрать результаты")
    p_collect.add_argument("-o", "--output", default="cracked.txt", help="Выходной файл")
    p_collect.set_defaults(func=cmd_collect)

    # instances
    p_inst = sub.add_parser("instances", help="Показать инстансы Vast.ai")
    p_inst.set_defaults(func=cmd_instances)

    # reset
    p_reset = sub.add_parser("reset", help="Очистить состояние")
    p_reset.add_argument("-f", "--force", action="store_true", help="Без подтверждения")
    p_reset.set_defaults(func=cmd_reset)

    # search
    p_search = sub.add_parser("search", help="Поиск GPU на маркетплейсе")
    p_search.add_argument("-g", "--gpu", default=None, help="Название GPU (например RTX 4090)")
    p_search.add_argument("-n", "--num-gpus", type=int, default=1, help="Мин. кол-во GPU (default: 1)")
    p_search.add_argument("--min-cost", type=float, default=0.0, help="Мин. $/hr (default: 0)")
    p_search.add_argument("-c", "--max-cost", type=float, default=5.0, help="Макс. $/hr (default: 5.0)")
    p_search.add_argument("--min-ram", type=int, default=8, help="Мин. VRAM в GB (default: 8)")
    p_search.add_argument("-l", "--limit", type=int, default=20, help="Макс. результатов (default: 20)")
    p_search.set_defaults(func=cmd_search)

    # rent
    p_rent = sub.add_parser("rent", help="Арендовать инстанс по Offer ID")
    p_rent.add_argument("offer_id", type=int, help="ID оффера из search")
    p_rent.add_argument("--image", default="nvidia/cuda:12.4.0-devel-ubuntu22.04", help="Docker image")
    p_rent.add_argument("--disk", type=int, default=30, help="Диск GB (default: 30)")
    p_rent.add_argument("-w", "--wait", action="store_true", help="Ждать пока инстанс станет running")
    p_rent.set_defaults(func=cmd_rent)

    # destroy
    p_destroy = sub.add_parser("destroy", help="Уничтожить инстанс")
    p_destroy.add_argument("instance_id", type=int, help="ID инстанса")
    p_destroy.add_argument("-f", "--force", action="store_true", help="Без подтверждения")
    p_destroy.set_defaults(func=cmd_destroy)

    # destroy-all
    p_destroy_all = sub.add_parser("destroy-all", help="Уничтожить все инстансы")
    p_destroy_all.add_argument("-f", "--force", action="store_true", help="Без подтверждения")
    p_destroy_all.set_defaults(func=cmd_destroy_all)

    # deploy
    p_deploy = sub.add_parser("deploy", help="Загрузить и распаковать архив на инстансы")
    p_deploy.add_argument("archive", nargs="?", default=None, help="Путь к архиву (.zip, .tar.gz, .tgz, .tar.bz2, .tar.xz, .7z)")
    p_deploy.add_argument("--url", default=None, help="URL для скачивания архива прямо на инстансы (быстрее)")
    p_deploy.add_argument("-i", "--instances", default=None, help="ID инстансов через запятую (по умолчанию: все running)")
    p_deploy.add_argument("-d", "--dir", default=None, help="Директория распаковки (default: /root/hashcrack)")
    p_deploy.set_defaults(func=cmd_deploy)

    # ssh-setup
    p_ssh_setup = sub.add_parser("ssh-setup", help="Настройка SSH ключа для Vast.ai")
    p_ssh_setup.set_defaults(func=cmd_ssh_setup)

    # exec
    p_exec = sub.add_parser("exec", help="Выполнить команду на всех инстансах")
    p_exec.add_argument("cmd", help="Команда для выполнения")
    p_exec.add_argument("-i", "--instances", default=None, help="ID инстансов через запятую")
    p_exec.add_argument("-t", "--timeout", type=int, default=30, help="Таймаут в секундах (default: 30)")
    p_exec.set_defaults(func=cmd_exec)

    # cost
    p_cost = sub.add_parser("cost", help="Показать расходы и баланс")
    p_cost.set_defaults(func=cmd_cost)

    # logs
    p_logs = sub.add_parser("logs", help="Показать hashcat логи с инстанса")
    p_logs.add_argument("instance_id", type=int, nargs="?", default=None, help="ID инстанса")
    p_logs.add_argument("-n", "--lines", type=int, default=50, help="Кол-во строк (default: 50)")
    p_logs.add_argument("-f", "--follow", action="store_true", help="Следить за логами в реальном времени")
    p_logs.set_defaults(func=cmd_logs)

    # ssh
    p_ssh = sub.add_parser("ssh", help="SSH подключение к инстансу")
    p_ssh.add_argument("instance_id", type=int, nargs="?", default=None, help="ID инстанса")
    p_ssh.set_defaults(func=cmd_ssh)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()