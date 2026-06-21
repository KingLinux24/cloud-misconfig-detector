# Cloud Misconfiguration Report (IaC)

Total findings: 3

## Top Findings

### 1. S3 public access block disabled or partially disabled (CRITICAL) | Risk 100
Category: Public Data Exposure
Resource: aws_s3_bucket_public_access_block.public_block
File: data/raw/terraform/s3_public.tf

Evidence:
{'block_public_acls': 'false', 'block_public_policy': 'false', 'ignore_public_acls': 'false', 'restrict_public_buckets': 'false'}

Remediation:
Enable all S3 public access block settings and verify bucket policies and ACLs.


### 2. RDS storage encryption disabled (HIGH) | Risk 85
Category: Data Protection
Resource: aws_db_instance.db
File: data/raw/terraform/rds_unencrypted.tf

Evidence:
{'storage_encrypted': False}

Remediation:
Enable storage encryption for databases handling sensitive data; plan migration if required.


### 3. Admin port exposed to the internet (HIGH) | Risk 80
Category: Network Exposure
Resource: aws_security_group_rule.ssh_open
File: data/raw/terraform/sg_open.tf

Evidence:
{'from_port': 22, 'to_port': 22, 'cidr_blocks': ['0.0.0.0/0']}

Remediation:
Restrict ingress to trusted IP ranges, use VPN/bastion, and enforce MFA for admin access.

