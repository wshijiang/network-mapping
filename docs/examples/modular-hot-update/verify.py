"""Compile and exercise real worker replacement. Requires Python 3 and rustc only."""
import argparse
import pathlib
import queue
import subprocess
import tempfile
import threading
import time


def verify(rustc):
    source = pathlib.Path(__file__).with_name("prototype.rs")
    with tempfile.TemporaryDirectory(prefix="nm-hot-update-") as temporary:
        root = pathlib.Path(temporary)
        v1, v2, bad = (root / name for name in ("v1", "v2", "bad"))
        for artifact, flags in ((v1, []), (v2, ["--cfg", "enhanced"])):
            subprocess.run(
                [rustc, "--edition=2024", *flags, str(source), "-o", str(artifact)],
                check=True,
            )
        bad.write_text("#!/bin/sh\nprintf 'READY 99 bad\\n'\n")
        bad.chmod(0o700)
        process = subprocess.Popen(
            [str(v1), "host", str(v1), str(v2), str(bad)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        events = queue.Queue()
        seen = []
        pending = []

        def read_output(stream, channel):
            for line in stream:
                events.put((channel, line.strip()))

        readers = [
            threading.Thread(target=read_output, args=(stream, channel), daemon=True)
            for stream, channel in ((process.stdout, "out"), (process.stderr, "err"))
        ]
        for reader in readers:
            reader.start()

        def send(command):
            process.stdin.write(command + "\n")
            process.stdin.flush()

        def expect(prefix):
            deadline = time.monotonic() + 8
            while True:
                for index, (channel, line) in enumerate(pending):
                    if channel == "out" and line.startswith(prefix):
                        pending.pop(index)
                        return line
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AssertionError(f"Missing {prefix!r}; output: {seen!r}")
                try:
                    event = events.get(timeout=remaining)
                except queue.Empty as exception:
                    raise AssertionError(f"Missing {prefix!r}; output: {seen!r}") from exception
                seen.append(event)
                pending.append(event)

        try:
            send(f"ACTIVATE 0 {v1} v1")
            assert expect("ACTIVE") == "ACTIVE 1 v1"
            send("CALL 1 1000 2")
            assert expect("PINNED") == "PINNED 1 1 v1"
            send(f"ACTIVATE 1 {v2} v2")
            assert expect("ACTIVE") == "ACTIVE 2 v2"
            send("CALL 2 0 2")
            assert expect("PINNED") == "PINNED 2 2 v2"
            assert expect("DONE 2 ") == "DONE 2 2 RESULT v2 20"
            assert expect("DONE 1 ") == "DONE 1 1 RESULT v1 2"
            send(f"ACTIVATE 1 {v1} v1")
            assert "revision conflict" in expect("REJECTED")
            send(f"ACTIVATE 2 {bad} bad")
            assert "protocol or build mismatch" in expect("REJECTED")
            send(f"ACTIVATE 2 {v1} v2")
            assert "protocol or build mismatch" in expect("REJECTED")
            send("ACTIVATE 2 /bin/true v1")
            assert "allowlist" in expect("REJECTED")
            send("CALL 3 0 3")
            assert expect("PINNED") == "PINNED 3 2 v2"
            assert expect("DONE 3 ") == "DONE 3 2 RESULT v2 30"
            # Rollback publishes a new revision instead of moving revision backwards.
            send(f"ACTIVATE 2 {v1} v1")
            assert expect("ACTIVE") == "ACTIVE 3 v1"
            send("CALL 4 0 3")
            assert expect("PINNED") == "PINNED 4 3 v1"
            assert expect("DONE 4 ") == "DONE 4 3 RESULT v1 3"
            send("QUIT")
            assert process.wait(timeout=8) == 0
            for reader in readers:
                reader.join(timeout=2)
            while not events.empty():
                seen.append(events.get_nowait())
            stops = [line for channel, line in seen if channel == "err" and line.startswith("STOP")]
            # v1, v2, two rejected children, and the rollback v1 are all reaped.
            assert len(stops) == 5, seen
        finally:
            if process.poll() is None:
                # EOF makes the host drain calls and drop all child process handles.
                process.stdin.close()
                process.wait(timeout=8)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        print("PASS: old request pinned, new code active, stale publication rejected,")
        print("      incompatible/unlisted artifacts rejected, rollback monotonic, children reaped")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", default="rustc")
    verify(parser.parse_args().rustc)
