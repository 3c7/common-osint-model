from binascii import hexlify
from hashlib import sha256


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


def unflatten(flattened: dict) -> dict:
    """
    Unflattens a dictionary
    :param flattened: Flattened dictionary
    :return: Unflattened dictionary
    """
    unflattened = {}
    for key, value in flattened.items():
        parts = key.split(".")
        d = unflattened
        for part in parts[:-1]:
            if part not in d:
                d[part] = dict()
            d = d[part]
        d[parts[-1]] = value
    return unflattened


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
            cns = value["tls"].get("certificate", {}).get("subject", {}).get("common_name", None) or list()
            for cn in cns:
                # Sloppy check if this is a real domain
                if "." in cn:
                    domains.append({"type": "common_name", "value": cn})
    return domains


def sha256_from_body_string(b: str) -> str:
    """
    Returns the sha256 hash of an html body given as string
    :param b: html body as string
    :return: hex digest of sha256 hash
    """
    h = sha256()
    h.update(bytes(b.encode("utf8")))
    return hexlify(h.digest()).decode("ascii")


def list_cleanup(d: dict) -> dict:
    for k, v in d.items():
        if isinstance(v, dict):
            d[k] = list_cleanup(v)
        elif isinstance(v, list):
            if len(v) == 1:
                d[k] = v[0]
    return d
