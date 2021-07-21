# JCEd25519

JCEd25519 is a JavaCard implementation of Ed25519 signing using public JavaCard API.

The implementation uses (modified) [JCMathLib library](https://github.com/OpenCryptoProject/JCMathLib) to perform necessary operations like EC and BigInt arithmetic. And in case SHA512 is not supported by given JavaCard, its [software re-implementation](https://www.fi.muni.cz/~xsvenda/jcalgs.html) is used.

Structure of this repository is based on [JavaCard Gradle Template](https://github.com/ph4r05/javacard-gradle-template).

## Usage

- Clone this repository

```bash
git clone --recursive https://github.com/dufkan/JCEd25519
```

- Build the applet

```bash
./gradlew buildJavaCard  --info --rerun-tasks
```

## APDU

TODO
