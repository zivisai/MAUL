"""Entrypoint for any lab agent container. Picks a service via SERVICE_NAME."""

import importlib
import os
import sys

import uvicorn

from shared.tls import server_uvicorn_kwargs


def main() -> int:
    service_name = os.environ.get("SERVICE_NAME", "").strip()
    if not service_name:
        print("SERVICE_NAME env var is required", file=sys.stderr)
        return 2
    port = int(os.environ.get("PORT", "8443"))
    try:
        module = importlib.import_module(f"services.{service_name}")
    except ImportError as e:
        print(f"could not import services.{service_name}: {e}", file=sys.stderr)
        return 2
    app = getattr(module, "app", None)
    if app is None:
        print(f"services.{service_name} has no `app`", file=sys.stderr)
        return 2
    print(f"[lab] {service_name} starting on port {port} (mTLS)")
    uvicorn.run(app, log_level="info", **server_uvicorn_kwargs(service_name, port=port))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
