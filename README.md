                    KeyManager
KeyManager ----------------------------------> registry
                RegisterKeyManager(km)



              tinkpb.KeyTemplate
keyset ------------------------------------> KeyHandle
                NewHandle(kt)



                    KeyHandle
tink-package -------------------------> Primitive 



     keyset.Manager           keyset.Handle
             \                   /
              \                 /
               \               /
                 tinkpb.Keyset


    KeyType ------------> KeyTemplate
     类型常量               预定义模版



            LocalKms ----------------------------> tinkaead.KMSEnvelopeAEAD
                |
           _____|______
           |           |
           |           |
         Store ----> SecretLock 