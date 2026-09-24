#!/usr/bin/env python3
"""Mutation tests for the ePDS private-stack boundary validator."""

import copy
import unittest

from validate_template import (
    EPDS_ENTRY,
    REGISTRY_PREFIX,
    TemplateContractError,
    validate_compose,
    validate_definition,
    validate_registry,
)


def valid_definition():
    hosts = {
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
    return {
        "routes": [
            {"id": key, "service": service, "hostname": host, "port": port}
            for key, (service, host, port) in hosts.items()
        ]
    }


def valid_compose():
    private_plc = "https://plc.atmosbox.test"
    return {
        "services": {
            "epds-core": {
                "environment": {
                    "PDS_PUBLIC_URL": "https://epds.atmosbox.test",
                    "PDS_DID_PLC_URL": private_plc,
                }
            },
            "epds-demo": {"environment": {"PLC_DIRECTORY_URL": private_plc}},
            "epds-demo-untrusted": {
                "environment": {"PLC_DIRECTORY_URL": private_plc}
            },
        },
        "networks": {"atmosinabox": {"internal": True}},
    }


def valid_registry():
    items = []
    for component_id, file_path, application in REGISTRY_PREFIX:
        item = {"id": component_id, "file": file_path}
        if application:
            item.update(
                application=application,
                definition=f"stacks/{application}.definition.json",
            )
        items.append(item)
    items.append(EPDS_ENTRY.copy())
    return items


class TemplateValidatorTests(unittest.TestCase):
    def test_accepts_private_routes_network_and_plc(self):
        validate_definition(valid_definition())
        validate_compose(valid_compose())

    def test_rejects_missing_canonical_route_host(self):
        definition = valid_definition()
        definition["routes"][0]["hostname"] = ""
        with self.assertRaisesRegex(TemplateContractError, "route contract"):
            validate_definition(definition)

    def test_rejects_public_plc_url_on_either_demo(self):
        config = valid_compose()
        config["services"]["epds-demo"]["environment"]["PLC_DIRECTORY_URL"] = (
            "https://plc.directory"
        )
        with self.assertRaisesRegex(TemplateContractError, "Private PLC URL"):
            validate_compose(config)

    def test_rejects_host_published_ports(self):
        config = valid_compose()
        config["services"]["epds-core"]["ports"] = ["3000:3000"]
        with self.assertRaisesRegex(TemplateContractError, "Host-published ports"):
            validate_compose(config)

    def test_rejects_changed_registry_schema(self):
        registry = copy.deepcopy(valid_registry())
        registry[0]["unexpected"] = "schema drift"
        with self.assertRaisesRegex(TemplateContractError, "registry schema/order"):
            validate_registry(registry)


if __name__ == "__main__":
    unittest.main()
