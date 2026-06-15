import yaml


def parse_cloudformation(content: str) -> list[dict]:
    """Parse CloudFormation YAML and return a flat list of resources."""
    data = yaml.safe_load(content)
    resources: list[dict] = []
    for logical_id, resource in (data.get("Resources") or {}).items():
        rtype = resource.get("Type", "")
        props = resource.get("Properties", {}) or {}
        resources.append({"type": rtype, "name": logical_id, "config": props})
    return resources
