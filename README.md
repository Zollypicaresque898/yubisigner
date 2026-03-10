# yubisigner

Hardware-based, multi-standard file signing with YubiKey  
yubisign is a compact GUI program for signing and verifying  
files with YubiKey. It supports international cryptographic  
standards and offers maximum security through hardware keys. 

**Please note:** No Yubikey is required for signature verification.

## Features

YubiKey hardware security  

- 4 hash algorithms: RIPEMD-256, SHA-256, SM3 and Streebog-256  
- RFC-compliant signatures with CRLF  
- Compact GUI with dark/light mode  
- Identicon for author verification (see [yubicrypt](https://github.com/Ch1ffr3punk/yubicrypt))  
- UTF-8 support for international characters in author string  
  of detached .sig file

## Example Signature file (.sig)
```
Author: Ch1ffr3punk
Signed at: 2026-03-10 17:04:52 +0000
Filename: yubisigner-windows-amd64.exe
File size: 25783808 bytes
Email: ch1ffr3punk@gmail.com
Telefax: n/a
URL: https://oc2mx.net
Comment: Release v0.1.1
  RIPEMD-256: d802a088c5630f68938954d53d4598f22b013f6312dbb60df51610073011fbeb
     SHA-256: f0bed5fe9e6d39d9ae6d6f8bdc6dafc6e2e6d9e25fea6a2eac994c48751bfe04
         SM3: 72a5136ee9d45595d6dc6934c9f4b17082f8328d2ba49359c5355df024d8deee
Streebog-256: 31c50403a17acb7ec4912acffb573dc0a3edaa3cf901d08f1d655591368d6c95
-----BEGIN YUBISIGNER ED25519 SIGNATURE-----
8a5f8adfec9690b8ae6ca95dc23811463fcce5bbba0d841f49b7d3f7a89ad149
c5d2c9dc1698cd93f22c4cb37c9122fbc529df810bafc2c3f3da1d4893df03ed
24ab15e151552fa4e6d42a6902eceef69a8a38523803a7208fdd8e7c57af3e03
-----END YUBISIGNER ED25519 SIGNATURE-----
```
![yubisigner](img/1.png)

![yubisigner](img/2.png)  

If you like yubisigner, as much as I do,  consider a small          
donation in crypto currencies or buy me a coffee.           
```  
BTC: bc1qkluy2kj8ay64jjsk0wrfynp8gvjwet9926rdel       
Nym: n1f0r6zzu5hgh4rprk2v2gqcyr0f5fr84zv69d3x       
XMR: 45TJx8ZHngM4GuNfYxRw7R7vRyFgfMVp862JqycMrPmyfTfJAYcQGEzT27wL1z5RG1b5XfRPJk97KeZr1svK8qES2z1uZrS        
```
<a href="https://www.buymeacoffee.com/Ch1ffr3punk" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-yellow.png" alt="Buy Me A Coffee" height="41" width="174"></a>

yubisigner is dedicated to Alice and Bob.  




