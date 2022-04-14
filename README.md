# JCEd25519

JCEd25519 is a JavaCard implementation of Ed25519 signing using public JavaCard API.

The implementation uses (modified) [JCMathLib library](https://github.com/OpenCryptoProject/JCMathLib) to perform necessary operations like EC and BigInt arithmetic. And in case SHA512 is not supported by given JavaCard, its [software re-implementation](https://www.fi.muni.cz/~xsvenda/jcalgs.html) is used.

Structure of this repository is based on [JavaCard Gradle Template](https://github.com/ph4r05/javacard-gradle-template).

## Usage

- Clone this repository


```bash
git clone --recursive https://github.com/dufkan/JCEd25519
```
- Select your JavaCard in JCEd25519.java file

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

The implementation was tested on J3R180, J2E145G.
