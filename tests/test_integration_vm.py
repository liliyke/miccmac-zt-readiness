"""Opt-in integration test: really SSHes into a live target and runs a full
assessment. Auto-skipped whenever the target env vars aren't set, so a plain
`pytest` run stays hermetic by default -- this file is the one deliberate
exception to the project's "no live target in tests" discipline.

Requires a reachable target with osquery installed and the connector's SSH
key authorized. Configure via environment variables:
    MICCMAC_TEST_VM_HOST, MICCMAC_TEST_VM_USER, MICCMAC_TEST_VM_SSH_KEY

Run explicitly with those set, e.g.:
    $env:MICCMAC_TEST_VM_HOST = "192.168.48.136"
    $env:MICCMAC_TEST_VM_USER = "miccmac"
    $env:MICCMAC_TEST_VM_SSH_KEY = "D:\\VMs\\ssh\\miccmac_vm_key"
    pytest tests/test_integration_vm.py -v
"""
import os

import pytest

from miccmac.checks import inventoried
from miccmac.connectors.ssh_osquery import SSHOsqueryConnector
from miccmac.engine import run_assessment
from miccmac.model import Status

VM_HOST = os.environ.get("MICCMAC_TEST_VM_HOST")
VM_USER = os.environ.get("MICCMAC_TEST_VM_USER")
VM_SSH_KEY = os.environ.get("MICCMAC_TEST_VM_SSH_KEY")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (VM_HOST and VM_USER and VM_SSH_KEY),
        reason="MICCMAC_TEST_VM_HOST/USER/SSH_KEY not set -- no live target configured",
    ),
]


def test_ssh_osquery_connector_collects_real_facts():
    connector = SSHOsqueryConnector(ssh_user=VM_USER, ssh_key_path=VM_SSH_KEY)
    facts = connector.collect_facts(VM_HOST)

    assert facts["os"]["platform"] == "ubuntu"
    assert isinstance(facts["deb_packages"], list)
    assert len(facts["deb_packages"]) > 0


def test_inventoried_property_against_real_target():
    connector = SSHOsqueryConnector(ssh_user=VM_USER, ssh_key_path=VM_SSH_KEY)
    facts = connector.collect_facts(VM_HOST)
    prop = inventoried.evaluate(VM_HOST, {"facts": facts})

    assert len(prop.checks) == 4
    assert all(c.status != Status.NOT_IMPLEMENTED for c in prop.checks)
    inv03 = next(c for c in prop.checks if c.check_id == "INV-03")
    assert inv03.status == Status.PASS


def test_full_assessment_against_real_target_with_inventory_record():
    connector = SSHOsqueryConnector(ssh_user=VM_USER, ssh_key_path=VM_SSH_KEY)
    facts = connector.collect_facts(VM_HOST)
    inventory_record = {"device_id": "integration-test", "tracked": True,
                        "last_reviewed": "2026-08-01"}

    assessment = run_assessment(
        VM_HOST, context={"facts": facts, "inventory_record": inventory_record},
        methodology_name="cmmi",
    )

    inv = next(p for p in assessment.properties if p.key == "inventoried")
    assert inv.score is not None
    assert assessment.methodology is not None
    assert assessment.methodology.properties["inventoried"].level is not None
