from pathlib import Path
from src.parse.terraform_parser import parse_terraform_dir
from src.rules.aws_rules import run_all_rules
from src.scoring.score import score_findings
from src.reporting.write_json import write as write_json
from src.reporting.write_md import write as write_md

def main():
    tf_dir = Path("data/raw/terraform")
    print(f"[*] Scanning directory: {tf_dir.absolute()}")
    
    resources = parse_terraform_dir(tf_dir)
    print(f"[*] Parsed {len(resources)} resources successfully.")

    findings = run_all_rules(resources)
    print(f"[*] Rule Engine execution finished. Found {len(findings)} misconfigurations.")

    scored = score_findings(findings)

    report = {
        "resource_count": len(resources),
        "finding_count": len(scored),
        "findings": scored
    }

    write_json(report, Path("data/processed/report.json"))
    write_md(scored, Path("docs/examples/report.md"))
    print("[+] Reports written to data/processed/report.json and docs/examples/report.md")

if __name__ == "__main__":
    main()
