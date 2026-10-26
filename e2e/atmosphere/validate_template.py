#!/usr/bin/env python3
"""Validate ePDS invariants that are outside AiaB's managed-stack schema."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse


REQUIRED_ROUTES = {
    "pds": ("epds-core", "epds", 3000),
    "pds-accounts": ("epds-core", "*.epds", 3000),
    "auth": ("epds-auth", "auth.epds", 3001),
    "authority": ("epds-lexicon-authority", "authority", 3000),
    "authority-accounts": ("epds-lexicon-authority", "*.authority", 3000),
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
    """Raised when the ePDS private-stack boundary is missing."""


def validate_definition(definition: object) -> None:
    if not isinstance(definition, dict) or not isinstance(definition.get("routes"), list):
        raise TemplateContractError("Managed app definition has no routes list")
    routes = {route.get("id"): route for route in definition["routes"] if isinstance(route, dict)}
    for route_id, (service, expected_host, port) in REQUIRED_ROUTES.items():
        route = routes.get(route_id)
        actual_host = None if route is None else route.get("host") or route.get("hostname")
        if (
            route is None
            or actual_host != expected_host
            or route.get("service") != service
            or route.get("port") != port
        ):
            raise TemplateContractError(f"Managed route contract is missing or changed: {route_id}")

    authority = definition.get("authority")
    if not isinstance(authority, dict) or authority.get("name") != "epds-lexicon-authority":
        raise TemplateContractError("Managed lexicon authority is missing")
    txt = definition.get("txt")
    owners = {entry.get("owner") for entry in txt or [] if isinstance(entry, dict)}
    if owners != {"_lexicon.hypercerts.org", "_lexicon.certified.app"}:
        raise TemplateContractError("Private lexicon TXT declarations are missing")


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


def _services(config: object) -> dict[str, object]:
    if not isinstance(config, dict):
        raise TemplateContractError("Rendered Compose config is not an object")
    services = config.get("services")
    if not isinstance(services, dict):
        raise TemplateContractError("Rendered Compose config has no services")
    return services


def _validate_no_host_ports(services: dict[str, object]) -> None:
    for name, service in services.items():
        if isinstance(service, dict) and service.get("ports"):
            raise TemplateContractError(f"Host-published ports are not allowed: {name}")


def _validate_internal_network(config: object) -> None:
    if not isinstance(config, dict):
        raise TemplateContractError("Rendered Compose config is not an object")
    networks = config.get("networks", {})
    app_network = networks.get("atmosinabox") if isinstance(networks, dict) else None
    if not isinstance(app_network, dict) or app_network.get("internal") is not True:
        raise TemplateContractError("Sandbox application network must remain internal")


def _expected_private_plc(services: dict[str, object]) -> str:
    core = services.get("epds-core")
    public_url = _environment(core, "PDS_PUBLIC_URL")
    plc_url = _environment(core, "PDS_DID_PLC_URL")
    public_host = urlparse(public_url or "").hostname or ""
    if not public_host.startswith("epds."):
        raise TemplateContractError("Core PDS public route is missing")
    expected_plc = f"https://plc.{public_host.removeprefix('epds.')}"
    if plc_url != expected_plc or urlparse(plc_url or "").hostname == "plc.directory":
        raise TemplateContractError("Core PDS must use the private sandbox PLC")
    return expected_plc


def _validate_dependent_plc_services(services: dict[str, object], expected_plc: str) -> None:
    for service_name, variable in REQUIRED_PLC_SERVICES.items():
        value = _environment(services.get(service_name), variable)
        if value != expected_plc or urlparse(value or "").hostname == "plc.directory":
            raise TemplateContractError(f"Private PLC URL is missing or changed: {service_name}")


def validate_compose(config: object) -> None:
    services = _services(config)
    _validate_no_host_ports(services)
    _validate_internal_network(config)
    expected_plc = _expected_private_plc(services)
    _validate_dependent_plc_services(services, expected_plc)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--definition", type=Path)
    parser.add_argument("--compose", nargs="?", const="-")
    args = parser.parse_args()

    if args.definition:
        validate_definition(json.loads(args.definition.read_text(encoding="utf-8")))
    if args.compose is not None:
        rendered = sys.stdin.read() if args.compose == "-" else Path(args.compose).read_text()
        validate_compose(json.loads(rendered))
    print("Template validation passed")


if __name__ == "__main__":
    main()
