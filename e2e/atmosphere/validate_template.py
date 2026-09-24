#!/usr/bin/env python3
"""Validate the ePDS managed-app contract without revealing rendered env values."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse


REGISTRY_PREFIX = (
    ("networking", "compose/networking.yaml", None),
    ("plc", "compose/plc.yaml", None),
    ("pds", "compose/pds.yaml", None),
    ("runner", "compose/runner.yaml", None),
    (
        "vanillajs-oauth-web-app",
        "stacks/vanillajs-oauth-web-app.yaml",
        "vanillajs-oauth-web-app",
    ),
)
EPDS_ENTRY = {
    "id": "epds-e2e",
    "file": "stacks/epds-e2e.yaml",
    "application": "epds-e2e",
    "definition": "stacks/epds-e2e.definition.json",
}
REQUIRED_ROUTES = {
    "pds": ("epds-core", "epds", 3000),
    "auth": ("epds-auth", "auth.epds", 3001),
    "lexicon-authority": ("epds-lexicon-authority", "lexicons", 3005),
    "trusted-demo": ("epds-demo", "trusted-demo.atmosbox.internal", 3002),
    "untrusted-demo": (
        "epds-demo-untrusted",
        "untrusted-demo.atmosbox.internal",
        3002,
    ),
    "mailpit": ("epds-mailpit", "mailpit", 8025),
}
REQUIRED_PLC_SERVICES = {
    "epds-core": "PDS_DID_PLC_URL",
    "epds-demo": "PLC_DIRECTORY_URL",
    "epds-demo-untrusted": "PLC_DIRECTORY_URL",
}


class TemplateContractError(ValueError):
    """Raised when a rendered ePDS stack violates the private test boundary."""


def validate_registry(items: object) -> list[dict[str, object]]:
    if not isinstance(items, list) or len(items) < len(REGISTRY_PREFIX):
        raise TemplateContractError("Pinned sandbox registry is missing components")

    for index, (component_id, file_path, application) in enumerate(REGISTRY_PREFIX):
        item = items[index]
        expected_keys = {"id", "file"}
        if application is not None:
            expected_keys |= {"application", "definition"}
        if (
            not isinstance(item, dict)
            or item.get("id") != component_id
            or item.get("file") != file_path
            or set(item) != expected_keys
        ):
            raise TemplateContractError("Pinned sandbox registry schema/order changed")
        if application is not None and (
            item.get("application") != application
            or item.get("definition") != f"stacks/{application}.definition.json"
        ):
            raise TemplateContractError("Pinned sandbox managed-app schema changed")

    matches = [item for item in items if isinstance(item, dict) and item.get("id") == "epds-e2e"]
    if len(matches) > 1 or (matches and matches[0] != EPDS_ENTRY):
        raise TemplateContractError("Existing epds-e2e registry entry changed")
    return items


def register_template(registry_path: Path) -> None:
    items = validate_registry(json.loads(registry_path.read_text(encoding="utf-8")))
    if not any(item.get("id") == EPDS_ENTRY["id"] for item in items):
        items.append(EPDS_ENTRY.copy())
    registry_path.write_text(json.dumps(items, indent=2) + "\n", encoding="utf-8")


def validate_definition(definition: object) -> None:
    if not isinstance(definition, dict) or not isinstance(definition.get("routes"), list):
        raise TemplateContractError("Managed app definition has no routes list")
    routes = {route.get("id"): route for route in definition["routes"] if isinstance(route, dict)}
    for route_id, (service, expected_host, port) in REQUIRED_ROUTES.items():
        route = routes.get(route_id)
        actual_host = None if route is None else route.get("host") or route.get("hostname")
        if (
            route is None
            or not actual_host
            or actual_host != expected_host
            or route.get("service") != service
            or route.get("port") != port
        ):
            raise TemplateContractError(f"Managed route contract is missing or changed: {route_id}")


def _environment(service: object, name: str) -> str | None:
    if not isinstance(service, dict):
        return None
    environment = service.get("environment", {})
    if isinstance(environment, dict):
        value = environment.get(name)
        return value if isinstance(value, str) else None
    if isinstance(environment, list):
        for item in environment:
            if isinstance(item, str) and item.startswith(f"{name}="):
                return item.split("=", 1)[1]
    return None


def validate_compose(config: object) -> None:
    if not isinstance(config, dict):
        raise TemplateContractError("Rendered Compose config is not an object")
    services = config.get("services")
    if not isinstance(services, dict):
        raise TemplateContractError("Rendered Compose config has no services")
    for name, service in services.items():
        if isinstance(service, dict) and service.get("ports"):
            raise TemplateContractError(f"Host-published ports are not allowed: {name}")

    networks = config.get("networks", {})
    app_network = networks.get("atmosinabox") if isinstance(networks, dict) else None
    if not isinstance(app_network, dict) or app_network.get("internal") is not True:
        raise TemplateContractError("Sandbox application network must remain internal")

    core = services.get("epds-core")
    public_url = _environment(core, "PDS_PUBLIC_URL")
    plc_url = _environment(core, "PDS_DID_PLC_URL")
    public_host = urlparse(public_url or "").hostname or ""
    if not public_host.startswith("epds."):
        raise TemplateContractError("Core PDS public route is missing")
    expected_plc = f"https://plc.{public_host.removeprefix('epds.')}"
    if plc_url != expected_plc or urlparse(plc_url or "").hostname == "plc.directory":
        raise TemplateContractError("Core PDS must use the private sandbox PLC")

    for service_name, variable in REQUIRED_PLC_SERVICES.items():
        value = _environment(services.get(service_name), variable)
        if value != expected_plc or urlparse(value or "").hostname == "plc.directory":
            raise TemplateContractError(f"Private PLC URL is missing or changed: {service_name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--register", type=Path)
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--compose", nargs="?", const="-")
    args = parser.parse_args()

    if args.register:
        register_template(args.register)
    if args.definition:
        validate_definition(json.loads(args.definition.read_text(encoding="utf-8")))
    if args.compose is not None:
        rendered = sys.stdin.read() if args.compose == "-" else Path(args.compose).read_text()
        validate_compose(json.loads(rendered))
    print("Template validation passed")


if __name__ == "__main__":
    main()
