def flatten(d: dict, parent_key: str = "") -> dict:
    """
    Flattens a dictonary so the attributes are accessible like the results of the censys api
    :param d: dictionary
    :param parent_key: parent key (used for recursion)
    :return: flattened dict (of level x, in recursion)
    """
    items = []
    for key, value in d.items():
        combined_key = "{}.{}".format(parent_key, key) if parent_key != "" else key
        try:
            items.extend(flatten(value, combined_key).items())
        except AttributeError:
            items.append((combined_key, value))
    return dict(items)


def common_model_cn_extraction(g: dict) -> list:
    """
    Loops through all keys in the already converted model in order to find domains
    :param g: dictionary of generic model
    :return: list of domain objects
    """
    domains = []
    for key, value in g.items():
        if not isinstance(value, dict):
            continue

        if "tls" in value.keys():
            for cn in (
                value["tls"]
                .get("certificate", {})
                .get("subject", {})
                .get("common_name", [])
            ):
                # Sloppy check if this is a real domain
                if "." in cn:
                    domains.append({"type": "common_name", "value": cn})
    return domains
