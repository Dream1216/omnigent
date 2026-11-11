"""Fixed exec-server stdio transport to an already bound private Session socket."""

from __future__ import annotations

import argparse
import contextlib
import os
import socket
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from omnigent.runner.session_channels import SessionRelayChannel, verify_session_socket


@dataclass(frozen=True)
class SessionExecutorEndpoint:
    """Transport identity supplied by the trusted Session executor owner."""

    session_id: str
    runner_id: str
    generation: str
    socket_path: Path
    device: int
    inode: int

    def verify(self, model: SessionRelayChannel) -> None:
        model.verify(session_id=self.session_id, runner_id=self.runner_id)
        if self.generation != model.generation:
            raise ValueError("Executor generation differs from its Session")
        verify_session_socket(self.socket_path, device=self.device, inode=self.inode)

    @property
    def environment_id(self) -> str:
        return "session_" + self.session_id.replace("-", "")

    def environment_config(self, model: SessionRelayChannel) -> str:
        import tomlkit

        self.verify(model)
        name = self.environment_id
        return tomlkit.dumps(
            {
                "default": name,
                "include_local": False,
                "environments": [
                    {
                        "id": name,
                        "program": sys.executable,
                        "args": [
                            "-I",
                            "-m",
                            __name__,
                            "--socket",
                            str(self.socket_path),
                            "--device",
                            str(self.device),
                            "--inode",
                            str(self.inode),
                        ],
                    }
                ],
            }
        )


def forward_stdio(path: Path, *, device: int, inode: int, stdin: int, stdout: int) -> None:
    """Copy the existing protocol unchanged; this connector never executes tools."""
    verify_session_socket(path, device=device, inode=inode)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
        stream.connect(str(path))
        verify_session_socket(path, device=device, inode=inode)

        def send_input() -> None:
            try:
                while data := os.read(stdin, 65536):
                    stream.sendall(data)
            except OSError:
                pass
            finally:
                with contextlib.suppress(OSError):
                    stream.shutdown(socket.SHUT_WR)

        sender = threading.Thread(target=send_input, daemon=True)
        sender.start()
        try:
            while data := stream.recv(65536):
                pending = memoryview(data)
                while pending:
                    written = os.write(stdout, pending)
                    if written == 0:
                        raise BrokenPipeError("Executor client stopped reading")
                    pending = pending[written:]
        finally:
            with contextlib.suppress(OSError):
                stream.shutdown(socket.SHUT_RDWR)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, required=True)
    parser.add_argument("--device", type=int, required=True)
    parser.add_argument("--inode", type=int, required=True)
    args = parser.parse_args()
    forward_stdio(
        args.socket,
        device=args.device,
        inode=args.inode,
        stdin=sys.stdin.fileno(),
        stdout=sys.stdout.fileno(),
    )


if __name__ == "__main__":
    main()
