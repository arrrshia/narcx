#!/usr/bin/env python3
"""Run a command inside a fresh pseudo-terminal, relaying stdin -> pty and pty -> stdout.

Used by scripts/audit.mjs so interactive TUIs boot the way they would in a real
terminal even though the harness itself has no tty. Exits with the child's
exit code (128 + signal if it was killed). Window size defaults to 120x40.
"""
import fcntl
import os
import pty
import select
import struct
import sys
import termios

argv = sys.argv[1:]
if not argv:
    sys.exit("usage: pty-run.py <command> [args...]")

pid, master = pty.fork()
if pid == 0:  # child: has the pty as its controlling terminal
    try:
        os.execvp(argv[0], argv)
    except OSError as e:
        sys.stderr.write(f"pty-run: {argv[0]}: {e.strerror}\n")
        os._exit(127)

cols = int(os.environ.get("NARC_PTY_COLS", "120"))
rows = int(os.environ.get("NARC_PTY_ROWS", "40"))
fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

stdin_fd = sys.stdin.fileno()
stdout_fd = sys.stdout.fileno()
watch = [master, stdin_fd]
while True:
    try:
        ready, _, _ = select.select(watch, [], [])
    except InterruptedError:
        continue
    if master in ready:
        try:
            data = os.read(master, 65536)
        except OSError:
            data = b""
        if not data:
            break  # child closed the pty
        os.write(stdout_fd, data)
    if stdin_fd in ready:
        try:
            data = os.read(stdin_fd, 65536)
        except OSError:
            data = b""
        if not data:
            watch.remove(stdin_fd)  # harness closed stdin; keep relaying output
        else:
            os.write(master, data)

_, status = os.waitpid(pid, 0)
if os.WIFSIGNALED(status):
    sys.exit(128 + os.WTERMSIG(status))
sys.exit(os.WEXITSTATUS(status))
