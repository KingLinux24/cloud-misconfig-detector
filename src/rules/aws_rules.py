from typing import Any, Dict, List
from src.utils.schema import Finding

def unwrap(val: Any) -> Any:
    """Safely extracts a scalar value from deeply nested HCL2 lists."""
    while isinstance(val, list):
        if len(val) == 0:
            return None
        val = val[0]
    return val

def rule_open_admin_ports(resources: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for r in resources:
        if r["type"] == "aws_security_group_rule":
            b = r["body"]
            r_type = unwrap(b.get("type"))
            
            if r_type == "ingress":
                # Safely parse ports, ignoring potential conversion errors
                try:
                    fp = int(unwrap(b.get("from_port", -1)))
                    tp = int(unwrap(b.get("to_port", -1)))
                except (ValueError, TypeError):
                    continue
                
                # Normalize cidr_blocks to a flat list of strings
                raw_cidrs = b.get("cidr_blocks", [])
                cidr_list = []
                if isinstance(raw_cidrs, list):
                    for item in raw_cidrs:
                        if isinstance(item, list):
                            cidr_list.extend([str(i) for i in item])
                        else:
                            cidr_list.append(str(item))
                
                if "0.0.0.0/0" in cidr_list and (fp in {22, 3389} or tp in {22, 3389}):
                    findings.append(Finding(
                        id=f"AWS-SG-OPEN-{r['name']}",
                        title="Admin port exposed to the internet",
                        severity="high",
                        category="Network Exposure",
                        resource=r,
                        evidence={"from_port": fp, "to_port": tp, "cidr_blocks": cidr_list},
                        remediation="Restrict ingress to trusted IP ranges, use VPN/bastion, and enforce MFA for admin access.",
                        references=[]
                    ))
    return findings

def rule_public_s3_block_disabled(resources: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for r in resources:
        if r["type"] == "aws_s3_bucket_public_access_block":
            b = r["body"]
            
            # Convert values to strings to prevent boolean/string comparison mismatches
            flags = {
                "block_public_acls": str(unwrap(b.get("block_public_acls"))).lower(),
                "block_public_policy": str(unwrap(b.get("block_public_policy"))).lower(),
                "ignore_public_acls": str(unwrap(b.get("ignore_public_acls"))).lower(),
                "restrict_public_buckets": str(unwrap(b.get("restrict_public_buckets"))).lower()
            }
            
            if any(v == "false" for v in flags.values()):
                findings.append(Finding(
                    id=f"AWS-S3-PUBLIC-{r['name']}",
                    title="S3 public access block disabled or partially disabled",
                    severity="critical",
                    category="Public Data Exposure",
                    resource=r,
                    evidence=flags,
                    remediation="Enable all S3 public access block settings and verify bucket policies and ACLs.",
                    references=[]
                ))
    return findings

def rule_rds_unencrypted(resources: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    for r in resources:
        if r["type"] == "aws_db_instance":
            enc = str(unwrap(r["body"].get("storage_encrypted"))).lower()
            if enc == "false":
                findings.append(Finding(
                    id=f"AWS-RDS-ENC-{r['name']}",
                    title="RDS storage encryption disabled",
                    severity="high",
                    category="Data Protection",
                    resource=r,
                    evidence={"storage_encrypted": False},
                    remediation="Enable storage encryption for databases handling sensitive data; plan migration if required.",
                    references=[]
                ))
    return findings

def run_all_rules(resources: List[Dict[str, Any]]) -> List[Finding]:
    findings: List[Finding] = []
    findings += rule_open_admin_ports(resources)
    findings += rule_public_s3_block_disabled(resources)
    findings += rule_rds_unencrypted(resources)
    return findings
