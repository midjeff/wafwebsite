"""Bound process lifetime and captured output; does not sanitize commands."""
import os
import signal
import subprocess
import threading


def ping_arguments():
    return ["ping", "-n", "1", "-w", "1000"] if os.name == "nt" else ["ping", "-c", "1", "-W", "1"]


def bounded_run(command, *, shell=False, timeout=3, limit=8192):
    process = subprocess.Popen(
        command, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        start_new_session=(os.name != "nt"),
    )
    output = bytearray()
    limited = threading.Event()

    def terminate():
        try:
            if os.name == "nt":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def drain():
        while True:
            block = process.stdout.read(512)
            if not block:
                return
            remaining = limit - len(output)
            output.extend(block[:remaining])
            if len(block) > remaining:
                limited.set()
                terminate()
                return

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
    finally:
        # Kill remaining descendants even if the shell has already exited.
        terminate()
        process.wait(timeout=2)
        reader.join(timeout=2)
        if not reader.is_alive():
            process.stdout.close()
    text = output.decode("utf-8", errors="replace")
    if timed_out:
        text += "\n[Превышено время выполнения]"
    if limited.is_set():
        text += "\n[Вывод ограничен 8192 байтами]"
    return text
