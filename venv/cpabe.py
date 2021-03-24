
from charm.toolbox.pairinggroup import PairingGroup, ZR,G1,G2, GT, pair, H, hashPair,order,pairing
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
import  sys,hashlib,time, string,random
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
        g =self.group.random(G1)
        print(type(g**2))



        #Randomly selects the variables required
        alpha = self.group.random(ZR)
        beta_1 = self.group.random(ZR)
        beta_2 = self.group.random(ZR)
        beta_bar = self.group.random(ZR)
        # print("alpha", alpha)
        #parameter evaluation
        p = self.group.order()
        # print("p ::::::: ", p)

        beta = int(beta_1 + beta_2 ) % p
        print(type(beta))

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



    def rhoMap(self,mono_span_prog, index):
        i=0
        for key in mono_span_prog:
            if i == index:
                return key
            else :
                i = i+1
        return -1

    def getRowOfA(self, mono_span_prog, index):
        i = 0
        for key in mono_span_prog:
            if i == index:
                return mono_span_prog[key]
            else:
                i = i + 1
        return -1
    #
    # def randomString(self, length):
    #     letters = string.ascii_lowercase
    #     result = ''.join((random.choice(letters)) for x in range(length))
    #     return  result
    #


    def encrypt(self, pk,msk, msg, policy_str,univ):
        """
         Encrypt a message M under a policy string.
        """

        if debug:
            print('Encryption algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        print(mono_span_prog)
        c_i_prime = []
        d_i_prime = []
        for i in range(len(mono_span_prog.keys())):
            r_i  = self.group.random(ZR)
            c_i_prime.append(pk['g']** (r_i * pk['H'](int(self.rhoMap(mono_span_prog,i)))))
            d_i_prime.append(pk['g'] ** (r_i * msk['V_mu'][int(self.rhoMap(mono_span_prog,i))]))

        CT_prime = {'c_i_prime' :c_i_prime , 'd_i_prime':d_i_prime}




        R = random.randint(1000,1000000)
        r_dash = []
        lambda_i = []

        for i in range(len(mono_span_prog.keys())):
            r_dash.append(self.group.random(ZR))

        # print(mo/no_span_prog)
        for k in range(len(mono_span_prog.keys())):
            sum = 0
            temp = self.getRowOfA(mono_span_prog, k)
            for j in range(len(temp)):
                sum += temp[j] * r_dash[j]
            lambda_i.append(sum)


        s=r_dash[0]
        temp = msk['beta']
        c0 =  R * (pk['Y'] ** int(s))
        c1 = pk['g'] ** int(s)

        c_i= []
        for i in range(len(lambda_i)):
            c_i.append((pk['T0'] ** lambda_i[i])*(c_i_prime[i]))

        D_i = d_i_prime

        CT_ABE = {"c0": c0 ,"c1": c1, "CT_prime": CT_prime }

        return CT_ABE


    def IndexGen(self,pk,msk,inverted_index):
        dict = list(inverted_index.keys())
        pi =  self.group.random(ZR)
        psi = []
        i1 = [];i2 = [];i3 = []
        for i in range(len(dict)):
            psi.append(self.group.random(ZR))
            i1.append(pk['g']**(int(psi[i])*int(msk['beta_bar'])))
            temp = (pk['T0'] ** (int(psi[i]))) * (pk['T0'] ** (pi))
            temp2 = (pk['g'] ** (int(psi[i]) * int(pk['H'](dict[i]))))
            i2.append(temp*temp2)
            i3.append(pk['T0'] ** pi)

        Index_ = {"i1":i1,"i2":i2,"i3":i3}
        return Index_


    def TrapGen(self,kw,USK,pk,msk):
        varphi = self.group.random(ZR)
        t_1 = (pk['T0'] ** (int(varphi))) * (pk['g'] ** (int(varphi) * int(pk['H'](kw))))
        t_2 = pk['g'] ** (int(varphi)*int(msk['beta_bar']))
        # t_3 = pk['T1']**varphi
        Eak = USK['E_ak']
        TD_ = {'t_1':t_1,'t_2':t_2,'E_ak':Eak}
        return TD_


    def search(self,Index_,TD_,ii):
        for i in range(len(Index_['i1'])):
            ptr = pair(Index_['i1'][i], TD_['t_1'])
            ptr1 = pair(Index_['i2'][i], TD_['t_2'])
            ptr2 = pair(Index_['i3'][i], TD_['t_2'])
            if ptr*ptr2 == ptr1:
                print("file found at the server")
                temp = ii[i]
                return temp
        print("file not found at the server")
        return -1




    def decrypt(self, pk, ctxt, key):
        """
         Decrypt ciphertext ctxt with key key.
        """

if debug:
        return (ctxt['c_m'] * prod) / (pair(key['k0'], ctxt['c0']))


