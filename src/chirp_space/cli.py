"""Chirp Space command-line entrypoint."""

from __future__ import annotations

import argparse

from chirp_space.web import create_app


def main() -> None:
    parser = argparse.ArgumentParser(prog="chirp-space")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve", help="Run the Space web server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--no-debug", action="store_true")
    subparsers.add_parser("migrate", help="Apply app-owned database migrations")
    subparsers.add_parser("check", help="Validate routes, templates, and configuration")
    args = parser.parse_args()

    app = create_app(debug=not getattr(args, "no_debug", False))
    if args.command == "serve":
        app.run(host=args.host, port=args.port)
        return
    if args.command == "check":
        result = app.check(warnings_as_errors=True)
        if result is not None:
            print(result)


if __name__ == "__main__":
    main()
