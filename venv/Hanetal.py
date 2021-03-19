


def encrypt(self, pk, msg, policy_str):
    """
     Encrypt a message M under a policy string.
    """

    if debug:
        print('Encryption algorithm:\n')

    policy = self.util.createPolicy(policy_str)
    mono_span_prog = self.util.convert_policy_to_msp(policy)
    num_cols = self.util.len_longest_row

    # pick randomness
    u = []
    for i in range(num_cols):
        rand = self.group.random(ZR)
        u.append(rand)
    s = u[0]  # shared secret

    c0 = pk['h'] ** s

    C = {}
    for attr, row in mono_span_prog.items():
        cols = len(row)
        sum = 0
        for i in range(cols):
            sum += row[i] * u[i]
        attr_stripped = self.util.strip_index(attr)
        c_i1 = pk['g2'] ** sum
        c_i2 = self.group.hash(str(attr_stripped), G1) ** sum
        C[attr] = (c_i1, c_i2)

    c_m = (pk['e_gg_alpha'] ** s) * msg

    return {'policy': policy, 'c0': c0, 'C': C, 'c_m': c_m}


def decrypt(self, pk, ctxt, key):
    """
     Decrypt ciphertext ctxt with key key.
    """

    if debug:
        print('Decryption algorithm:\n')

    nodes = self.util.prune(ctxt['policy'], key['attr_list'])
    if not nodes:
        print ("Policy not satisfied.")
        return None

    prod = 1

    for node in nodes:
        attr = node.getAttributeAndIndex()
        attr_stripped = self.util.strip_index(attr)
        (c_attr1, c_attr2) = ctxt['C'][attr]
        (k_attr1, k_attr2) = key['K'][attr_stripped]
        prod *= (pair(k_attr1, c_attr1) / pair(c_attr2, k_attr2))

    return (ctxt['c_m'] * prod) / (pair(key['k0'], ctxt['c0']))