





                   LocalKMS 
                      | |
      ________________| |_________________
      |                                  ｜
 KeyTemplate                        




                                                                                                                       LocalKMS
                                                                                                                __________|  |______________
                                                                                                                |                           |
                                                                                                                |                           |
                                                                                                                |                           | spikms.Store
                                                                                                            tink.AEAD
    KeyType                                 KeyTemplate                              registry
          
   AES128GCM                            AES128GCMKeyTemplate                        KeyManager --> plain Key  -->  ...   --> encrypted Key 
   AES256GCM                            AES256GCMKeyTemplate                        KeyManager
   AES256GCMNoPrefix                AES256GCMNoPrefixKeyTemplate                    KeyManager
   ChaCha20Poly1305                 ChaCha20Poly1305KeyTemplate
   XChaCha20Poly1305                XChaCha20Poly1305KeyTemplate

   ECDSAP256TypeDER                 SHA256 - NIST_P256 - DER - RAW
   ECDSAP384TypeDER                 SHA384 - NIST_P384 - DER - RAW  
   ECDSAP521TypeDER                 SHA521 - NIST_P521 - DER - RAW
   ECDSAP256TypeIEEEP1363           SHA256 - NIST_P256 - IEEE_P1363 - RAW
   ECDSAP384TypeIEEEP1363           SHA384 - NIST_P382 - IEEE_P1363 - RAW
   ECDSAP521TypeIEEEP1363           SHA532 - NIST_P521 - IEEE_P1363 - RAW

   ECDSASecp256k1TypeDER            SHA256 - SECP256k1 - DER - TINK
   ECDSASecp256k1TypeIEEEP1363      SHA256 - SECP256k1 - IEEE_P1363 - TINK

   ED25519                          Ed25519 - RAW                  
   
   RSARS256
   RASPS256
   
   HMACSHA256Tag256                 SHA256 - Tag256 - TINK

   NISTP256ECDHKW
   NISTP384ECDHKW
   NISTP521ECDHKW
   
   X25519ECDHKW

   BLS122381G2
   
   ClCredDef
   ClMasterSecret
            