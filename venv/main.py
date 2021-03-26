
import time,random
from charm.toolbox.pairinggroup import PairingGroup, GT
from cpabe import BSW07


def main():
    print("updated")
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('SS512')

    # AC17 CP-ABE under DLIN (2-linear)
    cpabe = BSW07(pairing_group, 2)
    kw = "modify"

    attr_list1 = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']
    user_attr  = ['1', '2','3','4']
    user_attr2 = ['2', '4', '9', '10']
    # attr_list1 = ['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21',
    #              '22','23','24','25','26','27','28','29','30','31','32','33','34','35','36','37','38','39','40',
    #             '41','42','43','44','45','46','47','48','49','50','51','52','53','54','55','56','57','58','59','60',
    #              '61','62','63','64','65','66','67','68','69','70','71','72','73','47','75','76','77','78','79','80',
    #              '81','82','83','84','85','86','87','88','89','90','91','92','93','94','95','96','97','98','99','100']

    inverted_index = {"simulation": ['1', '3', '4', '8'], "experiment": ['2', '3', '6', '8'],
                      "cluster": ['1', '2', '4', '6'], "modify": ['2', '4', '3', '5'],"test": ['6', '2', '1', '5'],
                      "webcam" : ['6', '2', '1', '5'],"video" : ['6', '2', '1', '5'],"main" : ['6', '2', '1', '5'],
                      "cpabe" : ['6', '2', '1', '5'],"python" : ['6', '2', '1', '5']}

    # run the set up
    attr_list1 = []
    setup_time = {}
    k = 10

    for l in range(10):
        print(k)
        for i in range(k):
            attr_list1.append(str(i))
        temp = 0
        for j in range(10):
            strt = time.clock()
            (pk, msk) = cpabe.setup(attr_list1)
            end = time.clock()
            temp = temp + (end-strt)*1000

        setup_time[k] = temp/10
        k = k+10


    sorted(setup_time.items(), key=lambda x: x[1])
    print("setup times", sorted(setup_time.items(), key=lambda x: x[1]))

    # generate a key
    keygen_time = {}
    user_attr = []
    k=10
    print("attribute list",len(attr_list1))
    for l in range(5):
        print(k)
        for i in range(k):
            user_attr.append(str(random.randint(1,50)))
        temp = 0
        for j in range(10):
            strt = time.clock()
            (USK, FSK) = cpabe.keygen(pk, msk, user_attr)
            end = time.clock()
            temp = temp + (end - strt) * 1000

        keygen_time[k] = temp / 10
        k = k + 10
    print("keygen times", sorted(keygen_time.items(), key=lambda x: x[1]))




    # choose a random message
    msg = pairing_group.random(GT)

    # generate a ciphertext
    policy_str = '((1 and 3) and (2 OR 4))'
    strt = time.clock()
    ctxt = cpabe.encrypt(pk,msk, msg, policy_str,attr_list1)
    end = time.clock()
    print("time for ciphertext generation :",(end - strt) * 1000)


    strt = time.clock()
    index_ = cpabe.IndexGen(pk,msk,inverted_index)
    end = time.clock()
    print("time for index generation :",(end - strt) * 1000)

    # print("index",index_)
    strt = time.clock()
    TD_ = cpabe.TrapGen(kw,USK,pk,msk)
    end = time.clock()
    print("time for trapdoor :",(end - strt) * 1000)
    # print("trapdoor",TD_)

    strt = time.clock()
    result = cpabe.search(index_,TD_,inverted_index)
    end = time.clock()
    print("time for search :",(end - strt) * 1000)
    # print("search results",result)

    # decryption
    strt = time.clock()
    rec_msg = cpabe.decrypt(pk,msk, ctxt, FSK, USK)
    end = time.clock()
    print("time for decryption :",(end - strt) * 1000)
   # if debug:
   #     if rec_msg == msg:
   #         print ("Successful decryption.")
   #     else:
   #         print ("Decryption failed.")

    #attribute revocation
    strt = time.clock()
    mu = '2'
    UFSK, UCT_ABE  = cpabe.attrRevocation(pk,msk, FSK, mu, ctxt)
    end = time.clock()
    print("time for revocation :",(end - strt) * 1000)


    # start = time.clock()
    # urevoke = cpabe.traceability(pk,USK,FSK)
    # end = time.clock()
    print("time for key sanity :",(end - strt) * 1000)

if __name__ == "__main__":
    debug = False
    main()
