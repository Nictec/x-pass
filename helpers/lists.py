def serialize_list(list):
    serialized = []
    for item in list:
        serialized.append(item.serialize())

    return serialized
