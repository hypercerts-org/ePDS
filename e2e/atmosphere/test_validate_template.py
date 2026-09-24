#!/usr/bin/env python3
"""Mutation tests for the ePDS private-stack boundary validator."""

import copy
import unittest

from validate_template import TemplateContractError, validate_compose, validate_definition


def valid_definition():
    hosts = {
        "pds": ("epds-core", "epds", 3000),
        "pds-accounts": ("epds-core", "*.epds", 3000),
        "auth": ("epds-auth", "auth.epds", 3001),
        "authority": ("epds-lexicon-authority", "authority", 3000),
        "authority-accounts": ("epds-lexicon-authority", "*.authority", 3000),
        "trusted-demo": ("epds-demo", "trusted-demo.atmosbox.internal", 3002),
        "untrusted-demo": ("epds-demo-untrusted", "untrusted-demo.atmosbox.internal", 3002),
        "mailpit": ("epds-mailpit", "mailpit", 8025),
    }
    return {
        "routes": [
            {"id": key, "service": service, "hostname": host, "port": port}
            for key, (service, host, port) in hosts.items()
        ],
        "authority": {"name": "epds-lexicon-authority"},
        "txt": [
            {"owner": "_lexicon.hypercerts.org"},
            {"owner": "_lexicon.certified.app"},
        ],
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
            "epds-demo-untrusted": {"environment": {"PLC_DIRECTORY_URL": private_plc}},
        },
        "networks": {"atmosinabox": {"internal": True}},
    }


class TemplateValidatorTests(unittest.TestCase):
    def test_accepts_private_routes_network_and_plc(self):
        validate_definition(valid_definition())
        validate_compose(valid_compose())

    def test_rejects_missing_wildcard_handle_route(self):
        definition = valid_definition()
        definition["routes"].pop(1)
        with self.assertRaisesRegex(TemplateContractError, "pds-accounts"):
            validate_definition(definition)

    def test_rejects_missing_lexicon_txt_record(self):
        definition = valid_definition()
        definition["txt"].pop()
        with self.assertRaisesRegex(TemplateContractError, "TXT"):
            validate_definition(definition)

    def test_rejects_public_plc_url_on_either_demo(self):
        config = valid_compose()
        config["services"]["epds-demo"]["environment"]["PLC_DIRECTORY_URL"] = "https://plc.directory"
        with self.assertRaisesRegex(TemplateContractError, "Private PLC URL"):
            validate_compose(config)

    def test_rejects_host_published_ports(self):
        config = valid_compose()
        config["services"]["epds-core"]["ports"] = ["3000:3000"]
        with self.assertRaisesRegex(TemplateContractError, "Host-published ports"):
            validate_compose(config)


if __name__ == "__main__":
    unittest.main()
