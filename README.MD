# WebCrypto quick & dirty POC

Quick WebCrypto POC created a long time ago.

AES Benchmark comparison of asmcrypto.js (GCM, CBC) vs WebCrypto API (GCM).

[Demo](https://0x6a61.github.io/Webcrypto-Demo/)

Implementation is most likely not secure:
**!!DON'T USE FOR CONFIDENTIAL FILES!!**

```
Results (Firefox 71.0 64-Bit; Arch-Linux; AMD FX-8350):
 
Webcrypto API: 775 ms
AsmCrypto (GCM): 4855 ms
AsmCrypto (CBC): 1950 ms
```
