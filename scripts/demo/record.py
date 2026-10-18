#!/usr/bin/env python3
"""Record docs/demo.gif: type the README quickstart into a real terminal and render it with agg.

Needs /dev/kvm, a built dist/terra, and agg:
cargo install --locked --git https://github.com/asciinema/agg --tag v1.7.0
"""

import argparse
import fcntl
import json
import os
import pty
import re
import select
import socket
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WIDTH, HEIGHT = 100, 27
TYPING_DELAY = 0.08
READING_PAUSE_LIMIT = 6
HOST_PROMPT = "$ "
GUEST_PROMPT = "/work $ "
DETACH_KEY = "\x1c"
REAL_HOME = f"{Path.home()}/"
DEMO_HOME = "/home/user/"
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07]*\x07")

# Each step types its keys, waits for the prompt that marks it done, then pauses for reading.
STEPS = [
    ("cat dev.yaml\r", HOST_PROMPT, 6.0),
    ("terra ./dev.yaml setup\r", HOST_PROMPT, 3.5),
    ("terra\r", GUEST_PROMPT, 2.0),
    ("ls\r", GUEST_PROMPT, 2.0),
    ("node index.js\r", GUEST_PROMPT, 2.5),
    ("wget -q --spider https://registry.npmjs.org && echo allowed\r", GUEST_PROMPT, 3.0),
    ("wget -q --spider https://example.com || echo blocked\r", GUEST_PROMPT, 5.5),
    (DETACH_KEY, HOST_PROMPT, 3.0),
    ("terra ls\r", HOST_PROMPT, 1.0),
]


def read_quickstart_recipe():
    readme = (ROOT / "README.md").read_text()
    quickstart = readme[readme.index("## Quickstart") :]
    return re.search(r"```yaml\n(.*?)```", quickstart, re.S).group(1)


class Recording:
    def __init__(self, fd):
        self.fd = fd
        self.start = time.monotonic()
        self.events = []
        self.screen_text = ""
        self.held_back = ""

    def pump(self, seconds):
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            if select.select([self.fd], [], [], remaining)[0]:
                self.read_available()

    def read_available(self):
        try:
            data = os.read(self.fd, 65536).decode(errors="replace")
        except OSError:
            data = ""
        if not data:
            raise RuntimeError("the demo shell exited early")
        self.record_output(data)

    def record_output(self, data):
        data = self.held_back + data
        # A home path split across reads would escape the alias, so its start waits for the rest.
        self.held_back = next(
            (data[-n:] for n in range(len(REAL_HOME) - 1, 0, -1) if data.endswith(REAL_HOME[:n])), ""
        )
        data = data[: len(data) - len(self.held_back)].replace(REAL_HOME, DEMO_HOME)
        if data:
            self.events.append([round(time.monotonic() - self.start, 3), "o", data])
            self.screen_text += ANSI.sub("", data).replace("\r", "")

    def type_and_wait(self, keys, prompt, timeout=300):
        marked = len(self.screen_text)
        for key in keys:
            os.write(self.fd, key.encode())
            self.pump(TYPING_DELAY)
        deadline = time.monotonic() + timeout
        while not self.screen_text[marked:].endswith(prompt):
            if time.monotonic() > deadline:
                raise RuntimeError(f"timed out waiting for {prompt!r}:\n{self.screen_text[-400:]}")
            self.pump(0.05)


def record(project, terra, cast):
    env = {
        "PATH": f"{terra.parent}:{os.environ['PATH']}",
        "HOME": os.environ["HOME"],
        "TERM": "xterm-256color",
        "PS1": HOST_PROMPT,
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    pid, fd = pty.fork()
    if pid == 0:
        os.chdir(project)
        os.execvpe("bash", ["bash", "--norc", "--noprofile", "-i"], env)
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", HEIGHT, WIDTH, 0, 0))
    recording = Recording(fd)
    recording.type_and_wait("", HOST_PROMPT, timeout=10)
    for keys, prompt, pause in STEPS:
        recording.type_and_wait(keys, prompt)
        recording.pump(pause)
    os.kill(pid, 9)
    recording.events.append([round(time.monotonic() - recording.start, 3), "o", recording.held_back])
    text = "".join(event[2] for event in recording.events)
    leaks = [private for private in (str(Path.home()), socket.gethostname()) if private in text]
    if leaks:
        raise RuntimeError(f"the recording shows {leaks}; alias them before publishing")
    with cast.open("w") as out:
        out.write(json.dumps({"version": 2, "width": WIDTH, "height": HEIGHT}) + "\n")
        out.writelines(json.dumps(event) + "\n" for event in recording.events)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--terra", type=Path, default=ROOT / "dist" / "terra")
    parser.add_argument("--project", type=Path, default=Path.home() / "myapp",
                        help=f"demo project folder; terra shows it with your home as {DEMO_HOME}")
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "demo.gif")
    args = parser.parse_args()
    terra, project = args.terra.resolve(), args.project
    if project.exists():
        sys.exit(f"{project} already exists; pass --project with a fresh path")
    project.mkdir(parents=True)
    try:
        (project / "dev.yaml").write_text(read_quickstart_recipe())
        (project / "index.js").write_text('console.log("hello from the box")\n')
        with tempfile.TemporaryDirectory() as scratch:
            cast = Path(scratch) / "demo.cast"
            record(project, terra, cast)
            subprocess.run(["agg", "--quiet", "--idle-time-limit", str(READING_PAUSE_LIMIT), "--last-frame-duration", "7",
                            "--theme", "github-dark", "--font-size", "16",
                            str(cast), str(args.output)], check=True)
    finally:
        subprocess.run([terra, "rm", "--force", "--purge"], cwd=project, check=False)
        shutil.rmtree(project)


if __name__ == "__main__":
    main()
