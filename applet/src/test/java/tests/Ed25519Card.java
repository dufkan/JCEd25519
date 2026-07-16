package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import jced25519.Consts;
import jced25519.jcmathlib;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Thin client wrapping the JCEd25519 APDU protocol for use from tests.
 *
 * The happy-path helpers ({@link #keygen}, {@link #sign}, {@link #signChunked})
 * assert a 0x9000 status and expected response lengths.
 *
 * Negative / error-path tests should build raw APDUs and use {@link #transmit}.
 */
class Ed25519Card {
    static final int SW_OK = 0x9000;

    final CardManager cm;
    private final ECCurve curve;

    Ed25519Card(CardManager cm) {
        this.cm = cm;
        this.curve = new ECCurve.Fp(
                new BigInteger(1, jcmathlib.Wei25519.p),
                new BigInteger(1, jcmathlib.Wei25519.a),
                new BigInteger(1, jcmathlib.Wei25519.b),
                new BigInteger(1, jcmathlib.Wei25519.r),
                BigInteger.valueOf(8)
        );
    }

    ResponseAPDU transmit(CommandAPDU cmd) throws Exception {
        ResponseAPDU r = cm.transmit(cmd);
        assertNotNull(r);
        assertNotNull(r.getBytes());
        return r;
    }

    /**
     * Generates a fresh key pair and returns the 32-byte Ed25519 public key.
     *
     * @param offload if true, the point-to-Ed25519 conversion is performed on
     *                the host and pushed back with INS_SET_PUB
     */
    byte[] keygen(boolean offload) throws Exception {
        ResponseAPDU r = transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_KEYGEN, offload ? 1 : 0, 0));
        assertEquals(SW_OK, r.getSW());
        byte[] data = r.getData();

        if (!offload) {
            assertEquals(32, data.length);
            return data;
        }

        assertEquals(65, data.length);
        byte[] pub = encodeEd25519(curve.decodePoint(data).multiply(BigInteger.valueOf(8)));
        ResponseAPDU setPub = transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SET_PUB, 0, 0, pub));
        assertEquals(SW_OK, setPub.getSW());
        return pub;
    }

    /** Signs {@code msg} in a single INS_SIGN_FINALIZE call, returning the 64-byte signature. */
    byte[] sign(byte[] msg, boolean offload) throws Exception {
        signInit(offload);
        return finalize(msg);
    }

    /**
     * Signs {@code msg} feeding it to the card in {@code chunkSize}-byte pieces via
     * INS_SIGN_UPDATE, with the trailing piece delivered by INS_SIGN_FINALIZE.
     */
    byte[] signChunked(byte[] msg, boolean offload, int chunkSize) throws Exception {
        signInit(offload);
        int off = 0;
        while (msg.length - off > chunkSize) {
            byte[] chunk = new byte[chunkSize];
            System.arraycopy(msg, off, chunk, 0, chunkSize);
            ResponseAPDU r = transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_UPDATE, chunk.length, 0, chunk));
            assertEquals(SW_OK, r.getSW());
            assertEquals(0, r.getData().length);
            off += chunkSize;
        }
        byte[] tail = new byte[msg.length - off];
        System.arraycopy(msg, off, tail, 0, tail.length);
        return finalize(tail);
    }

    private void signInit(boolean offload) throws Exception {
        ResponseAPDU r = transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_INIT, offload ? 1 : 0, 0));
        assertEquals(SW_OK, r.getSW());
        if (!offload) {
            assertEquals(0, r.getData().length);
            return;
        }
        assertEquals(65, r.getData().length);
        byte[] nonce = encodeEd25519(curve.decodePoint(r.getData()));
        ResponseAPDU set = transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_NONCE, 0, 0, nonce));
        assertEquals(SW_OK, set.getSW());
        assertEquals(0, set.getData().length);
    }

    private byte[] finalize(byte[] tail) throws Exception {
        ResponseAPDU r = transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_FINALIZE, tail.length, 0, tail));
        assertEquals(SW_OK, r.getSW());
        byte[] sig = r.getData();
        assertEquals(64, sig.length);
        return sig;
    }

    /** Verifies an Ed25519 signature using the reference net.i2p.crypto.eddsa implementation. */
    static boolean verify(byte[] publicKey, byte[] msg, byte[] signature) throws Exception {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        PublicKey pubKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(publicKey, spec));
        sgr.initVerify(pubKey);
        sgr.update(msg);
        return sgr.verify(signature);
    }

    /** Decodes a Weierstrass point returned by the card into a bouncycastle {@link ECPoint}. */
    ECPoint decodePoint(byte[] encoded) {
        return curve.decodePoint(encoded);
    }

    /** Host-side Weierstrass-to-Ed25519 point encoding (mirrors JCEd25519.encodeEd25519). */
    byte[] encodeEd25519(ECPoint point) {
        BigInteger p = new BigInteger(1, jcmathlib.Wei25519.p);
        BigInteger a3 = new BigInteger(1, Consts.TRANSFORM_A3);
        BigInteger c = new BigInteger(1, Consts.TRANSFORM_C);

        BigInteger x = point.normalize().getAffineXCoord().toBigInteger();
        BigInteger y = point.normalize().getAffineYCoord().toBigInteger();

        BigInteger tmp = x.subtract(a3).mod(p);

        boolean xBit = tmp.multiply(c).mod(p).multiply(y.modInverse(p)).mod(p).testBit(0);

        byte[] result = tmp.subtract(BigInteger.ONE).multiply(tmp.add(BigInteger.ONE).modInverse(p)).mod(p).toByteArray();
        byte[] output = new byte[32];
        int diff = output.length - result.length;
        for (int i = diff; i < output.length; ++i) {
            output[i] = result[i - diff];
        }
        output[0] |= xBit ? (byte) 0x80 : (byte) 0x00;
        for (int i = 0; i < output.length / 2; ++i) {
            byte t = output[output.length - i - 1];
            output[output.length - i - 1] = output[i];
            output[i] = t;
        }
        return output;
    }
}
