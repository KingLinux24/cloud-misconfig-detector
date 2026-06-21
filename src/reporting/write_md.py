from pathlib import Path
from jinja2 import Environment, FileSystemLoader

def write(findings: list[dict], out_path: Path):
    env = Environment(loader=FileSystemLoader("templates"))
    tpl = env.get_template("report.md.j2")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(tpl.render(findings=findings), encoding="utf-8")
