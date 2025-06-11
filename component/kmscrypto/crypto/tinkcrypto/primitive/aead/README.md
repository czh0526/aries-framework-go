                    KeyManager
KeyManager ----------------------------------> registry
                RegisterKeyManager(km)



              tinkpb.KeyTemplate
keyset ------------------------------------> KeyHandle
                NewHandle(kt)



                    KeyHandle
tink-package -------------------------> Primitive 



                  keyset
        ____________|___________
        |                       |
     Manager                  Handle
        \                       /
         \                     /
              tinkpb.Keyset