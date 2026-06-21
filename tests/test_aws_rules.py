import pytest
from src.rules.aws_rules import (
    rule_open_admin_ports,
    rule_public_s3_block_disabled,
    rule_rds_unencrypted,
)

def test_rule_open_admin_ports_flags_vulnerability():
    """Verify that an ingress rule with 0.0.0.0/0 on port 22 is flagged."""
    mock_resources = [{
        "file": "mock_sg.tf",
        "type": "aws_security_group_rule",
        "name": "ssh_anywhere",
        "body": {
            "type": "ingress",
            "from_port": 22,
            "to_port": 22,
            "cidr_blocks": ["0.0.0.0/0"]
        }
    }]
    
    findings = rule_open_admin_ports(mock_resources)
    assert len(findings) == 1
    assert findings[0].id == "AWS-SG-OPEN-ssh_anywhere"
    assert findings[0].severity == "high"


def test_rule_open_admin_ports_ignores_secure_configs():
    """Verify that a restricted CIDR or non-admin port is ignored."""
    mock_resources = [
        {
            "type": "aws_security_group_rule",
            "name": "ssh_secure",
            "body": {
                "type": "ingress",
                "from_port": 22,
                "to_port": 22,
                "cidr_blocks": ["192.168.1.0/24"]  # Private/Trusted IP range
            }
        },
        {
            "type": "aws_security_group_rule",
            "name": "http_anywhere",
            "body": {
                "type": "ingress",
                "from_port": 80,
                "to_port": 80,
                "cidr_blocks": ["0.0.0.0/0"]       # Port 80 is fine to expose
            }
        }
    ]
    
    findings = rule_open_admin_ports(mock_resources)
    assert len(findings) == 0


def test_rule_public_s3_block_disabled():
    """Verify that disabling public access block triggers a critical alert."""
    mock_resources = [{
        "file": "mock_s3.tf",
        "type": "aws_s3_bucket_public_access_block",
        "name": "leaky_bucket",
        "body": {
            "block_public_acls": False,
            "block_public_policy": False,
            "ignore_public_acls": True,
            "restrict_public_buckets": True
        }
    }]
    
    findings = rule_public_s3_block_disabled(mock_resources)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert findings[0].id == "AWS-S3-PUBLIC-leaky_bucket"


def test_rule_rds_unencrypted_flags_false():
    """Verify that an RDS instance with storage_encrypted=False is flagged."""
    mock_resources = [{
        "file": "mock_rds.tf",
        "type": "aws_db_instance",
        "name": "unencrypted_db",
        "body": {
            "storage_encrypted": False
        }
    }]
    
    findings = rule_rds_unencrypted(mock_resources)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_rule_rds_unencrypted_ignores_encrypted():
    """Verify that an RDS instance with storage_encrypted=True passes cleanly."""
    mock_resources = [{
        "file": "mock_rds.tf",
        "type": "aws_db_instance",
        "name": "secure_db",
        "body": {
            "storage_encrypted": True
        }
    }]
    
    findings = rule_rds_unencrypted(mock_resources)
    assert len(findings) == 0
