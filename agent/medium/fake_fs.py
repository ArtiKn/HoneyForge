"""A read-only, per-channel filesystem made entirely of fictitious strings."""
from __future__ import annotations

import posixpath
import re
import shlex


class FakeShell:
    def __init__(self, username: str) -> None:
        self.username = re.sub(r"[^a-zA-Z0-9_.-]", "_", username)[:64] or "guest"
        if self.username in (".", ".."):
            self.username = "guest"
        self.home = f"/home/{self.username}"
        self.cwd = self.home
        self.files = {
            f"{self.home}/README.txt": "Operations host. Application files are in /var/www/html.\n",
            "/etc/passwd": f"root:x:0:0:root:/root:/bin/bash\n{self.username}:x:1000:1000::/{self.home.lstrip('/')}:/bin/bash\n",
            "/etc/hostname": "web01\n",
            "/etc/os-release": 'NAME="Ubuntu"\nVERSION="22.04.4 LTS (Jammy Jellyfish)"\n',
            "/var/www/html/index.html": "<html><body>Administration portal</body></html>\n",
            "/var/www/html/config.php": "<?php $db_host='localhost'; $db_name='app'; $db_user='app_readonly'; ?>\n",
            "/var/log/auth.log": "Oct 16 09:00:00 web01 sshd: Server listening on 0.0.0.0 port 22.\n",
        }
        self.directories = {"/", "/tmp", "/root", self.home}
        for path in self.files:
            parent = posixpath.dirname(path)
            while parent != "/":
                self.directories.add(parent)
                parent = posixpath.dirname(parent)

    def path(self, value: str) -> str:
        if value == "~" or value.startswith("~/"):
            value = self.home + value[1:]
        return posixpath.normpath(posixpath.join(self.cwd, value))

    def execute(self, command: str) -> tuple[str, bool]:
        try:
            args = shlex.split(command)
        except ValueError:
            return "syntax error\r\n$ ", False
        if not args:
            return "$ ", False
        name, *operands = args
        if name in ("exit", "logout"):
            return "logout\r\n", True
        output = ""
        if name == "pwd" and not operands:
            output = self.cwd + "\n"
        elif name == "whoami" and not operands:
            output = self.username + "\n"
        elif name == "uname":
            output = "Linux web01 5.15.0-generic x86_64 GNU/Linux\n"
        elif name == "cd" and len(operands) <= 1:
            target = self.path(operands[0]) if operands else self.home
            if target in self.directories:
                self.cwd = target
            else:
                output = f"cd: {operands[0]}: No such directory\n"
        elif name == "ls":
            paths = [item for item in operands if not item.startswith("-")] or [self.cwd]
            for item in paths[:16]:
                path = self.path(item)
                if path in self.directories:
                    children = {posixpath.basename(p) for p in self.directories | self.files.keys()
                                if posixpath.dirname(p) == path and p != path}
                    output += "  ".join(sorted(children)) + "\n"
                elif path in self.files:
                    output += posixpath.basename(path) + "\n"
                else:
                    output += f"ls: {item}: No such file or directory\n"
        elif name == "cat" and operands:
            for item in operands[:16]:
                output += self.files.get(self.path(item), f"cat: {item}: No such file\n")
        elif name == "help":
            output = "pwd cd ls cat whoami uname exit\n"
        else:
            output = "command not found\n"
        return output.replace("\n", "\r\n") + "$ ", False
