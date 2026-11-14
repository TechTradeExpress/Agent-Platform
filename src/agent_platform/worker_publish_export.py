"""Worker-side export only. No credential, signer or network access."""

import argparse
import os

from .worker_publish_artifact import digest, encoded, export


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Export one exact local commit as inert bounded bytes."
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--output", required=True)
    a = parser.parse_args(argv)
    try:
        data, c = export(a.repository, a.head)
        fd = os.open(
            a.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                if n <= 0:
                    raise OSError
                view = view[n:]
            os.fsync(fd)
        finally:
            os.close(fd)
        print(
            encoded(
                {
                    "status": "EXPORTED",
                    "head": a.head,
                    "tree": c["tree"],
                    "parent": c["parents"][0],
                    "artifact_sha256": digest(data),
                }
            ).decode()
        )
        return 0
    except Exception:
        print('{"status":"BLOCKED","code":"export_stopped"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
