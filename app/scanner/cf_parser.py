import yaml


def _cf_loader() -> type:
    """Return a YAML loader that silently handles CloudFormation intrinsic tags (!Ref, !Sub, etc.)."""
    loader = yaml.SafeLoader

    def _ignore_tag(loader, tag_suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_mapping(node)

    yaml.add_multi_constructor("!", _ignore_tag, Loader=loader)
    return loader


def parse_cloudformation(content: str) -> list[dict]:
    """Parse CloudFormation YAML and return a flat list of resources."""
    data = yaml.load(content, Loader=_cf_loader())
    resources: list[dict] = []
    for logical_id, resource in (data.get("Resources") or {}).items():
        rtype = resource.get("Type", "")
        props = resource.get("Properties", {}) or {}
        resources.append({"type": rtype, "name": logical_id, "config": props})
    return resources
