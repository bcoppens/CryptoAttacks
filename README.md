This repository will contain some implementations of (side-channel) attacks against implementations of cryptographic algorithms. Each directory will contain some attack code, code to set up the attack, and a README that describes how to set it up and run the code.

For now, I have the following attack:
* [ecdsa](./ecdsa/): The attack by Howgrave-Graham and N.P. Smart on OpenSSL's ECDSA (in 2011) as discovered by B.B. Brumley and N. Tuveri.
