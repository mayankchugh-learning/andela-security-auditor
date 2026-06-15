import hcl2


def _unquote(value):
    """Recursively strip surrounding quotes that hcl2 v8+ adds to string values."""
    if isinstance(value, str):
        if len(value) >= 2 and value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        return value
    if isinstance(value, dict):
        return {k: _unquote(v) for k, v in value.items() if k != "__is_block__"}
    if isinstance(value, list):
        return [_unquote(v) for v in value]
    return value


def parse_terraform(content: str) -> list[dict]:
    """Parse HCL/Terraform content and return a flat list of resources."""
    data = hcl2.loads(content)
    resources: list[dict] = []
    for resource_block in data.get("resource", []):
        for rtype, instances in resource_block.items():
            rtype = rtype.strip('"')
            for rname, cfg in instances.items():
                rname = rname.strip('"')
                if isinstance(cfg, list) and len(cfg) == 1:
                    cfg = cfg[0]
                resources.append({"type": rtype, "name": rname, "config": _unquote(cfg)})
    return resources
