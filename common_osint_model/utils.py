import hashlib
from typing import Tuple

import mmh3


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


def hash_all(data: bytes) -> Tuple[str, str, str, str]:
    """
    Helper function to create all hashes for data given.

    :returns: Tuple of hashes as string: md5, sha1, sha256, murmur
    """
    md5, sha1, sha256, murmur = (
        hashlib.md5(),
        hashlib.sha1(),
        hashlib.sha256(),
        mmh3.hash(data),
    )
    md5.update(data), sha1.update(data), sha256.update(data)
    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest(), str(murmur)
