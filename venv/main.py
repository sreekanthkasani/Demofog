'''
:Authors:         Shashank Agrawal
:Date:            5/2016
'''
import time
from charm.toolbox.pairinggroup import PairingGroup, GT
from cpabe import BSW07


def main():
    print("updated")
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('SS512')

    # AC17 CP-ABE under DLIN (2-linear)
    cpabe = BSW07(pairing_group, 2)
    #attr_list = ['ONE', 'TWO', 'THREE','FOUR','FIVE','SIX','SEVEN','EIGHT','NINE','TEN','ONE1',
     #            'TWO1', 'THREE1','FOUR1','FIVE1','SIX1','SEVEN1','EIGHT1','NINE1','TEN1',
      #           'ONE2', 'TWO2', 'THREE2','FOUR2','FIVE2','SIX2','SEVEN2','EIGHT2','NINE2','TEN2',
       #          'ONE3', 'TWO3', 'THREE3','FOUR3','FIVE3','SIX3','SEVEN3','EIGHT3','NINE3','TEN3',
        #         'ONE4', 'TWO4', 'THREE4','FOUR4','FIVE4','SIX4','SEVEN4','EIGHT4','NINE4','TEN4']
    kw = "modify"

    attr_list1 = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10']
    user_attr = ['1', '2','3','4']
    # attr_list1 = ['1','2','3','4','5','6','7','8','9','10','11','12','13','14','15','16','17','18','19','20','21',
    #              '22','23','24','25','26','27','28','29','30','31','32','33','34','35','36','37','38','39','40',
    #             '41','42','43','44','45','46','47','48','49','50','51','52','53','54','55','56','57','58','59','60',
    #              '61','62','63','64','65','66','67','68','69','70','71','72','73','47','75','76','77','78','79','80',
    #              '81','82','83','84','85','86','87','88','89','90','91','92','93','94','95','96','97','98','99','100']

    inverted_index = {"simulation": ['1', '3', '4', '8'], "experiment": ['2', '3', '6', '8'],
                      "cluster": ['1', '2', '4', '6'], "modify": ['2', '4', '3', '5']}

    # run the set up
    strt = time.clock()
    (pk, msk) = cpabe.setup(attr_list1)
    end = time.clock()
    print ("Time for setup:", (end-strt)*1000)

    # generate a key
    strt1 = time.clock()
    (USK,FSK) = cpabe.keygen(pk, msk, user_attr)
    end1 = time.clock()
    print ("Time for keygen:", (end1 - strt1) * 1000)

    # choose a random message
    msg = pairing_group.random(GT)

    # generate a ciphertext
    policy_str = '((1 and 3) and (2 OR 4))'
    ctxt = cpabe.encrypt(pk,msk, msg, policy_str,attr_list1)
    print(ctxt)

    index_ = cpabe.IndexGen(pk,msk,inverted_index)
    print(index_)

    TD_ = cpabe.TrapGen(kw,USK,pk,msk)
    print(TD_)

    result = cpabe.search(index_,TD_,inverted_index)
    print("search results",result)

    # decryption
   # rec_msg = cpabe.decrypt(pk, ctxt, key)
   # if debug:
   #     if rec_msg == msg:
   #         print ("Successful decryption.")
   #     else:
   #         print ("Decryption failed.")


if __name__ == "__main__":
    debug = False
    main()
