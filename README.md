# JCEd25519

JCEd25519 is a JavaCard implementation of Ed25519 signature algorithm for smartcards that do not support [Named Elliptic Curves](https://blogs.oracle.com/java/post/java-card-31-cryptographic-extensions) and the [EdDSA signature algorithm](https://docs.oracle.com/en/java/javacard/3.1/jc_api_srvc/api_classic/javacard/security/Signature.html#SIG_CIPHER_EDDSA) introduced in JavaCard API version 3.1.

The implementation uses (modified) [JCMathLib library](https://github.com/OpenCryptoProject/JCMathLib) to perform necessary operations with elliptic curve points and modular arithmetic. In case SHA512 is not supported by a JavaCard, its [software re-implementation](https://www.fi.muni.cz/~xsvenda/jcalgs.html) is used.

## :warning: WARNING :warning:

This implementation is only suited for proof-of-concept purposes and **NOT for production use**. The implementation relies on the [JCMathLib library](https://github.com/OpenCryptoProject/JCMathLib), that provides the underlying low-level operations, but not in constant time. An attacker observing signing time with sufficient precision may be able to use this information to **extract the private key**.

## Usage

- Clone this repository with submodules


```bash
git clone --recursive https://github.com/dufkan/JCEd25519
```
- Configure your card type in `JCEd25519.java` file (currently are supported only [SIMULATOR](https://github.com/licel/jcardsim), J3R180, J2E145G)

- Build the applet

```bash
./gradlew buildJavaCard  --info --rerun-tasks
```

- Send initialize APDU `00DF000000` to the card. For example, using GlobalPlatform Pro

```bash
gp --apdu 00A404000C6A6365643235353139617070 --apdu 00DF000000 -d
```

## Details

The optimizations in the implementation require the nonce to be generated randomly to be secure; otherwise, the implementation could be made to reuse nonce for signing of a different challenge. This is a minor deviation from Ed25519 specification, but it cannot be externally observed, unless multiple signatures of the same data are issued.

## Supported Cards

The implementation was tested on NXP J3R180, NXP J2E145G.
