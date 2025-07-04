                    KeyManager
KeyManager ----------------------------------> registry
                RegisterKeyManager(km)



              tinkpb.KeyTemplate
keyset ------------------------------------> KeyHandle
                NewHandle(kt)



                    KeyHandle
tink-package -------------------------> Primitive 


    keyset.NewManager()                      keyset.NewHandle(kt)
    ----------                                       --------------- KeyTemplate  <---------- KeyType
             |             预定义模版                 ｜               
             |                                      ｜
             |            km.Handle()               ｜    
             |         ---------------------->      ｜
        keyset.Manager                         keyset.Handle
             |         <----------------------      |
             |      NewManagerFromHandle(kh)        |
             |                                      |
             |______________     ___________________|
                           |     |
                        tinkpb.Keyset







            LocalKms ----------------------------> tinkaead.KMSEnvelopeAEAD
                |
           _____|______
           |           |
           |           |
         Store ----> SecretLock 