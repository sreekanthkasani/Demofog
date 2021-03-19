
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1,G2, GT, pair, H, hashPair,order,pairing
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
import  sys,hashlib,time
debug = False


class BSW07(ABEnc):

    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.group = group_obj
        self.util = MSP(self.group, verbose)

    def hash(self,  args, type=ZR):
        return H(self.Pairing,args,type)

    def hash_0(self,  msg, nH0):
        m = hashlib.sha256(msg.encode()).hexdigest()
        res = "{0:08b}".format(int(m,16))
        return res

    def hash_1(self, msg):
        m = hashlib.sha256(msg.encode()).hexdigest()
        res = "{0:08b}".format(int(m, 16))
        return res

    def hash_2(self, msg, nH1):
        m = hashlib.sha256(msg.encode()).hexdigest()
        res = "{0:08b}".format(int(m, 16))
        return res


    def setup(self, attr_list1):
        """
        Generates public key and master secret key.
        """

        if debug:
            print('Setup algorithm:\n')
        strt_time = time.time()
        # pick a random element each from two source groups
        g = self.group.random(G1)

        #Randomly selects the variables required
        alpha = self.group.random(ZR)
        beta_1 = self.group.random(ZR)
        beta_2 = self.group.random(ZR)
        beta_bar = self.group.random(ZR)

        #parameter evaluation
        p = self.group.order()
        print(beta_1,beta_2, p)

        beta = int(beta_1 + beta_2 ) % p
        T0 = g ** alpha
        T1 = g ** beta_bar
        Y = pair(g,g) ** beta

        V = []
        Apk = []
        for i in range(0,len(attr_list1)):
            V.append(self.group.random(ZR))
            Apk.append(g ** int(attr_list1[i]))

        #setting PK and MSK
        pk = {'G1': G1, 'GT': GT, 'p': p, 'e' : G1,  'g': g, 'H' : hash, 'H0':self.hash_0 , 'H1': self.hash_1, 'H2':self.hash_2 ,'Y': Y, 'T0':T0,'T1': T1,'APK':Apk}
        msk = {'beta': beta,'beta_1': beta_1,'beta_2': beta_2,'alpha':alpha, 'beta_bar': beta_bar, 'V_mu': V}
        print(pk)
        print(msk)
        print ("%s", time.time()-strt_time)
        return pk, msk


    def FKeyGen(self, pk, msk,shrd, user_attr):
        k_s1 = pk['g'] ** (msk['beta_2']/shrd['m'])
        k_s2 = pk['g'] ** (shrd['l']/shrd['m'])
        F_ak = shrd['ak']

        print(msk['V_mu'])

        #
        k_mu = []
        for i in range(0, len(user_attr)):
            temp1 = shrd['l']/(msk['V_mu'][int(user_attr[i])-1])
            temp =  pk['H'](int(user_attr[i]))/shrd['m']
            temp = pk['g'] ** (temp*temp1)
            k_mu.append(temp)

        FSK = {'k_s1': k_s1  ,'k_s2':k_s2, 'k_mu':k_mu, 'F_ak': F_ak}

        return FSK


    def UKeyGen(self, pk, msk, shrd, user_attr):
        k_u1 = (pk['g'] ** msk['beta_1'])*(pk['g'] ** (msk['alpha']*shrd['l']))
        k_u2 = shrd['m']
        E_ak = shrd['ak']
        k_prime = pk['g'] ** (msk['alpha']*msk['beta_bar'])

        USK = {'k_u1':k_u1,'k_u2':k_u2,'k_prime':k_prime,'E_ak':E_ak}
        return USK

    def keygen(self, pk, msk,user_attr):
        """
        Generate a key for a set of attributes.
        """

        if debug:
            print('Key generation algorithm:\n')

        ak = self.group.random(ZR)
        l = self.group.random(ZR)
        m = self.group.random(ZR)

        shrd = {'ak': ak,'l':l,'m':m}

        FSK = self.FKeyGen(pk,msk,shrd,user_attr)
        USK = self.UKeyGen(pk,msk,shrd,user_attr)
        print("USK = " , USK)
        print("FSK =" , FSK)
        return USK, FSK

    def encrypt(self, pk, msg, policy_str,univ):
        """
         Encrypt a message M under a policy string.
        """

        if debug:
            print('Encryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        print(policy,mono_span_prog)
        print(num_cols)


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
            print("Policy not satisfied.")
            return None

        prod = 1

        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)
            (c_attr1, c_attr2) = ctxt['C'][attr]
            (k_attr1, k_attr2) = key['K'][attr_stripped]
            prod *= (pair(k_attr1, c_attr1) / pair(c_attr2, k_attr2))

        return (ctxt['c_m'] * prod) / (pair(key['k0'], ctxt['c0']))


