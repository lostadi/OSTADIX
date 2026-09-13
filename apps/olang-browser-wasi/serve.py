#!/usr/bin/env python3
"""Loopback-only development server for an emitted O browser bundle."""

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class BundleHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def send_head(self):
        root = Path(self.directory).resolve()
        target = Path(self.translate_path(self.path)).resolve()
        if target.is_dir():
            for filename in ("index.html", "index.htm"):
                candidate = target / filename
                if candidate.exists():
                    target = candidate.resolve()
                    break
        if not target.is_relative_to(root):
            self.send_error(403, "Path escapes bundle directory")
            return None
        return super().send_head()

    def list_directory(self, path):
        self.send_error(403, "Directory listing is disabled")
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    root = args.directory.resolve(strict=True)
    if not root.is_dir() or not (root / "manifest.json").is_file():
        parser.error("directory must contain an emitted browser bundle manifest")
    if not 0 <= args.port <= 65535:
        parser.error("port must be 0..65535")
    with ThreadingHTTPServer(("127.0.0.1", args.port), partial(BundleHandler, directory=str(root))) as server:
        print(f"O browser bundle: http://127.0.0.1:{server.server_port}/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
