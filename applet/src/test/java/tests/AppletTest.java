package tests;

import applet.Consts;
import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.junit.Assert;
import org.junit.jupiter.api.*;
import net.i2p.crypto.eddsa.EdDSAEngine;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class AppletTest extends BaseTest {
    
    public AppletTest() {
        // Change card type here if you want to use physical card
        setCardType(CardType.JCARDSIMLOCAL);
    }

    @BeforeAll
    public static void setUpClass() throws Exception {
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
    }

    public byte[] keygen(CardManager cm) throws Exception {
        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_ED25519, Consts.INS_KEYGEN,0, 0);
        final ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
        Assert.assertEquals(32, responseAPDU.getData().length);
        return responseAPDU.getData();
    }

    @Test
    public void keygen_and_sign() throws Exception {
        final CardManager cm = connect();

        byte[] pubkeyBytes = keygen(cm);

        byte[] data = new byte[32];
        for(int i = 0; i < data.length; ++i)
            data[i] = (byte) (0xff & i);

        final CommandAPDU cmd = new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN,0, 0, data);
        final ResponseAPDU responseAPDU = cm.transmit(cmd);
        Assert.assertNotNull(responseAPDU);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
        Assert.assertNotNull(responseAPDU.getBytes());
        Assert.assertEquals(32 + 32, responseAPDU.getData().length);
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
        PublicKey pubKey = new EdDSAPublicKey(new EdDSAPublicKeySpec(pubkeyBytes, spec));
        sgr.initVerify(pubKey);
        sgr.update(data);
        Assert.assertTrue(sgr.verify(responseAPDU.getData()));
    }
}
