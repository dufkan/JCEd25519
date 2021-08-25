package tests;

import jced25519.Consts;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import jced25519.jcmathlib;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.jupiter.api.*;
import net.i2p.crypto.eddsa.EdDSAEngine;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

public class AppletTest extends BaseTest {
    ECCurve curve;
    ECPoint generator;

    public AppletTest() {
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);

        curve = new ECCurve.Fp(
                new BigInteger(1, jcmathlib.Wei25519.p),
                new BigInteger(1, jcmathlib.Wei25519.a),
                new BigInteger(1, jcmathlib.Wei25519.b),
                new BigInteger(1, jcmathlib.Wei25519.r),
                BigInteger.valueOf(8)
        );
        generator = curve.decodePoint(jcmathlib.Wei25519.G);

    }

    private byte[] encodeEd25519(ECPoint point) {
        BigInteger p = new BigInteger(1, jcmathlib.Wei25519.p);
        BigInteger a3 = new BigInteger(1, Consts.TRANSFORM_A3);
        BigInteger c = new BigInteger(1, Consts.TRANSFORM_C);

        BigInteger x = point.normalize().getAffineXCoord().toBigInteger();
        BigInteger y = point.normalize().getAffineYCoord().toBigInteger();

        BigInteger tmp = x.subtract(a3).mod(p);

        boolean x_bit = tmp.multiply(c).mod(p).multiply(y.modInverse(p)).mod(p).testBit(0);

        // Compute Y
        byte[] result = tmp.subtract(BigInteger.ONE).multiply(tmp.add(BigInteger.ONE).modInverse(p)).mod(p).toByteArray();
        byte[] output = new byte[32];
        int diff = output.length - result.length;

        for(int i = diff; i < output.length; ++i) {
            output[i] = result[i - diff];
        }
        output[0] |= x_bit ? (byte) 0x80 : (byte) 0x00;
        for (short i = 0; i < (short) (output.length / 2); ++i) {
            byte t = output[output.length - i - 1];
            output[(short) (output.length - i - 1)] = output[i];
            output[i] = t;
        }

        return output;
    }

    public byte[] keygen(CardManager cm, boolean offload) throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_ED25519, Consts.INS_KEYGEN, offload ? 1 : 0, 0);
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
        Assert.assertEquals(offload ? 65 : 32, responseAPDU.getData().length);
        byte[] result = responseAPDU.getData();
        if (offload) {
            ECPoint publicKey = curve.decodePoint(result).multiply(BigInteger.valueOf(8));
            result = encodeEd25519(publicKey);
            cmd = new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SET_PUB, 0, 0, result);
            responseAPDU = cm.transmit(cmd);
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(0x9000, responseAPDU.getSW());
            Assert.assertNotNull(responseAPDU.getBytes());
        }
        return result;
    }

    public byte[] sign(CardManager cm, byte[] data, boolean offload) throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_INIT, offload ? 1 : 0, 0);
        ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
        Assert.assertEquals(offload ? 65 : 0, responseAPDU.getData().length);
        byte[] resp = responseAPDU.getData();
        if(offload) {
            cmd = new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_NONCE, 0, 0, encodeEd25519(curve.decodePoint(resp)));
            responseAPDU = cm.transmit(cmd);
            Assert.assertNotNull(responseAPDU);
            Assert.assertEquals(0x9000, responseAPDU.getSW());
            Assert.assertNotNull(responseAPDU.getBytes());
            Assert.assertEquals(0, responseAPDU.getData().length);
        }

        cmd = new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_UPDATE, 0, 0, new byte[0]);
        responseAPDU = cm.transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
        Assert.assertEquals(0, responseAPDU.getData().length);

        cmd = new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_FINALIZE, data.length, 0, data);
        responseAPDU = cm.transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
        Assert.assertEquals(64, responseAPDU.getData().length);
        return responseAPDU.getData();
    }

    @Test
    public void keygen_and_sign() throws Exception {
        final CardManager cm = connect();
        cm.transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_INITIALIZE, 0, 0));
        byte[] pubkeyBytes = keygen(cm, true);
        cm.transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_GET_PRIV, 0, 0));

        for(int j = 0; j < 256; ++j) {
            byte[] data = new byte[32];
            for (int i = 0; i < data.length; ++i)
                data[i] = (byte) ((0xff & i) + j);

            byte[] signature = sign(cm, data, true);

            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
            PublicKey pubKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(pubkeyBytes, spec));
            sgr.initVerify(pubKey);
            sgr.update(data);
            Assert.assertTrue(sgr.verify(signature));
        }
    }
}
