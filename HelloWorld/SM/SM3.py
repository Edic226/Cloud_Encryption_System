from gmssl import func, sm3


def sm3_hash(data):
    if type(data) == str:
        data = data.encode()
    return sm3.sm3_hash(func.bytes_to_list(data))
