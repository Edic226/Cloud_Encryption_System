from gmssl import sm9
from gmssl.optimized_field_elements import FQ, FQ2, FQ12


def get_master_public(mk):
    test = [[], [], [], []]
    for i in mk[0]:
        test[0].append(FQ2(i))
    for i in mk[1]:
        test[1].append(FQ(i))
    for i in mk[2]:
        test[2].append(FQ(i))
    test[3] = (FQ12(mk[3]))
    master_public = (tuple(test[0]), tuple(test[1]), tuple(test[2]), test[3])
    return master_public


def get_sign(data):
    n = data.find('%sign%')
    sign = eval(data[n+6:])
    data = data[:n]
    signature = (sign[0], (FQ2(sign[1][0]), FQ2(sign[1][1]), FQ2(sign[1][2])))
    return signature, data


def sm9_sign(master_public, master_secret, id, data):
    Da = sm9.private_key_extract('sign', master_public, master_secret, id)
    signature = sm9.sign(master_public, Da, data)
    signature = '%sign%' + str(signature)
    return signature


def sm9_verify(master_public, id, data, signature):
    verify = sm9.verify(master_public, id, data, signature)
    return verify
