"""Chirp Space command-line entrypoint."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime

from chirp_space.config import SpaceConfig
from chirp_space.delivery import DeliveryService, DeliveryWorker, HTTPSDeliveryTransport
from chirp_space.federation import FederationService
from chirp_space.store import store_from_url
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
    deliver = subparsers.add_parser(
        "deliver", help="Run one bounded batch of due federation deliveries"
    )
    deliver.add_argument("--limit", type=int, default=16)
    subparsers.add_parser("queue", help="Show bounded federation queue health")
    retry = subparsers.add_parser("retry-delivery", help="Retry one dead delivery")
    retry.add_argument("delivery_id")
    discard = subparsers.add_parser("discard-delivery", help="Discard one queued delivery")
    discard.add_argument("delivery_id")
    args = parser.parse_args()

    if args.command in {"deliver", "queue", "retry-delivery", "discard-delivery"}:
        config = SpaceConfig.from_env(debug=False)
        store = store_from_url(config.database_url)
        try:
            store.migrate()
            federation = FederationService(store, config)
            delivery = DeliveryService(store, federation)
            if args.command == "deliver":
                outcomes = DeliveryWorker(store, federation, HTTPSDeliveryTransport()).run_once(
                    limit=args.limit
                )
            elif args.command == "retry-delivery":
                delivery.retry_dead_letter(args.delivery_id)
                outcomes = ()
            elif args.command == "discard-delivery":
                delivery.discard(args.delivery_id)
                outcomes = ()
            else:
                outcomes = ()
            health = store.queue_health(now=datetime.now(UTC))
            print(
                f"processed={len(outcomes)} pending={health.pending} "
                f"retrying={health.retrying} dead={health.dead}"
            )
            if args.command == "queue":
                control = store.federation_control()
                print(
                    f"inbound_paused={control.inbound_paused} "
                    f"outbound_paused={control.outbound_paused}"
                )
                for peer in store.peer_queue_statuses():
                    print(
                        f"peer={peer.domain} pending={peer.pending} retrying={peer.retrying} "
                        f"dead={peer.dead} circuits={peer.open_circuits} "
                        f"last_error={peer.last_error or '-'}"
                    )
        finally:
            store.close()
        return

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
