from pathlib import Path
from typing import Any, Dict, List
import hcl2

def sanitize_value(val: Any) -> Any:
    """Recursively strip accidental literal quotes from keys, strings, and structures."""
    if isinstance(val, str):
        # Strip external and internal literal quotes
        cleaned = val.strip("'\"").strip()
        if cleaned.lower() == "false":
            return False
        if cleaned.lower() == "true":
            return True
        return cleaned
    elif isinstance(val, dict):
        return {k.strip("'\"").strip(): sanitize_value(v) for k, v in val.items()}
    elif isinstance(val, list):
        return [sanitize_value(item) for item in val]
    return val

def parse_terraform_dir(dir_path: Path) -> List[Dict[str, Any]]:
    resources: List[Dict[str, Any]] = []
    for tf_file in dir_path.glob("*.tf"):
        with tf_file.open("r", encoding="utf-8") as f:
            obj = hcl2.load(f)

        for block in obj.get("resource", []):
            for r_type, named in block.items():
                for r_name, body in named.items():
                    # Unpack python-hcl2's outer list wrapper securely
                    actual_body = body[0] if isinstance(body, list) and len(body) > 0 else body
                    
                    # Sanitize all literal quotes out of the keys/values
                    clean_type = r_type.strip("'\"").strip()
                    clean_name = r_name.strip("'\"").strip()
                    clean_body = sanitize_value(actual_body)
                    
                    resources.append({
                        "file": str(tf_file),
                        "type": clean_type,
                        "name": clean_name,
                        "body": clean_body
                    })
    return resources
