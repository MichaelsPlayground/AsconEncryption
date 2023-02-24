# Ascon Encryption

**Secure your device with ASCON, the new encryption standard for small devices (Java)**

On Feb. 7th. 2023 NIST (https://csrc.nist.gov/News/2023/lightweight-cryptography-nist-selects-ascon) 
announced the selection of the encryption algorithm family ASCON as new standard for encryption on small devices:

The team has decided to standardize the Ascon family for lightweight cryptography applications as it 
meets the needs of most use cases where lightweight cryptography is required. Congratulations to the 
Ascon team! NIST thanks all of the finalist teams and the community members who provided feedback that 
contributed to the selection.

My first impression was "why do we need a new encryption algorithm, we do have AES-CBC, AES-GCM and the 
Libsodium encryption schemes ?". But then I realized that these algorithms usually run fast on modern 
computers and smartphones because they have special instruction sets in their microcontrollers that 
optimize the algorithms running. The new algorithm is dedicated to those devices with a different 
chipset like Bluetooth beacons or sensors or NFC/RFID environments that run with limited resources 
("small devices").

The ASCON algorithm works very similar to the well known AES-GCM algorithm as it provides an authenticated 
encryption and can authenticate (unencrypted) additional data ("AEAD") as well.

This is the profile of the algorithm:
- encryption type: symmetric encryption
- key length: 128 bit (16 byte)
- block length: 128 bit (16 byte)
- nonce length: 128 bit (16 byte)
- authentication tag length: 128 bit (16 byte)

You find more details on the algorithm on the inventor`s website (https://ascon.iaik.tugraz.at/index.html); 
the latest specification update is  available on the NIST page: 
https://csrc.nist.gov/csrc/media/Projects/lightweight-cryptography/documents/finalist-round/status-updates/ascon-update.pdf. 

The algorithm was invented by Christoph Dobraunig, Maria Eichlseder, Florian Mendel and Martin Schläffer.

Find the complete article on Medium.com: https://medium.com/@androidcrypto/secure-your-device-with-ascon-the-new-encryption-standard-for-small-devices-java-ccb5447489c6

![client_view_after_connect](docs/Ascon01.png?raw=true)

![client_view_after_connect](docs/Ascon02.png?raw=true)

![client_view_after_connect](docs/Ascon03.png?raw=true)

![client_view_after_connect](docs/Ascon04.png?raw=true)

![client_view_after_connect](docs/Ascon05.png?raw=true)

Below you find some useful links:

Lightweight Cryptography Standardization Process: NIST Selects Ascon

NIST final chosen algorithm: https://csrc.nist.gov/News/2023/lightweight-cryptography-nist-selects-ascon

https://www.nist.gov/news-events/news/2023/02/nist-selects-lightweight-cryptography-algorithms-protect-small-devices

https://csrc.nist.gov/Projects/lightweight-cryptography/finalists

https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

https://csrc.nist.gov/csrc/media/Projects/lightweight-cryptography/documents/finalist-round/status-updates/ascon-update.pdf

Website: https://ascon.iaik.tugraz.at/index.html

Specification: https://ascon.iaik.tugraz.at/files/asconv12-nist.pdf

Java reference implementation: https://github.com/ascon/javaascon

KAT (Ascon128 v12): https://github.com/ascon/ascon-c/blob/main/crypto_aead/ascon128v12/LWC_AEAD_KAT_128_128.txt

KAT (Ascon128 av12): https://github.com/ascon/ascon-c/blob/main/crypto_aead/ascon128av12/LWC_AEAD_KAT_128_128.txt

BouncyCastle Test: https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/AsconTest.java

BouncyCastle KAT: https://github.com/bcgit/bc-java/tree/master/core/src/test/resources/org/bouncycastle/crypto/test/ascon

Medium: https://medium.com/asecuritysite-when-bob-met-alice/ascon-is-a-light-weight-champion-bfd81853d61a

Online: https://asecuritysite.com/light/lw_ascon

https://replit.com/@javacrypto/AsconEncryptionWithJava#Main.java
