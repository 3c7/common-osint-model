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
