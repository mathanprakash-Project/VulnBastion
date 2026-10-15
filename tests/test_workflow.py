"""
Unit tests for Agentic Remediation Workflow and Playbook Matching.
"""
import pytest
from workflow import RemediationCatalog, RemediationWorkflow, WorkflowState


def test_remediation_catalog_matching():
    catalog = RemediationCatalog()
    # Test Citrix match
    citrix_playbook = catalog.match_playbook("Citrix ADC Session Token Leak", "CVE-2023-4966")
    assert citrix_playbook is not None
    assert "Citrix" in citrix_playbook.technical_action or "Load Balancer" in citrix_playbook.finding_type
    assert citrix_playbook.priority_hint == "P0"

    # Test VPN match
    vpn_playbook = catalog.match_playbook("Fortinet SSL-VPN Heap Buffer Overflow RCE", "CVE-2024-21762")
    assert vpn_playbook is not None
    assert "VPN" in vpn_playbook.finding_type


def test_workflow_end_to_end(sample_risk_dict):
    workflow = RemediationWorkflow()
    state = workflow.run(sample_risk_dict)

    assert isinstance(state, WorkflowState)
    assert state.success is True
    assert state.error is None
    assert state.grounding_verified is True

    # Verify node execution history
    node_names = [record.node_name for record in state.execution_history]
    assert "IngestNode" in node_names
    assert "RetrievalNode" in node_names
    assert "SynthesisNode" in node_names
    assert "VerificationNode" in node_names
    assert "PlaybookNode" in node_names

    # Verify explanation and candidates
    assert len(state.candidates) > 0
    assert "nist_control_id" in state.explanation
    assert state.explanation["nist_control_id"] in [c["identifier"] for c in state.candidates]

