package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import jced25519.Consts;
import jced25519.JCEd25519;
import jced25519.jcmathlib;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.FileWriter;
import java.io.PrintWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Performance measurement of the offloaded signing flow.
 *
 * This is a benchmark rather than a correctness test: it records per-step
 * transmit times to {@code measurement.csv} and reads back the private nonce
 * (via the DEBUG-only INS_GET_PRIV_NONCE) for offline analysis. It is therefore
 * tagged {@code manual} so it is excluded from the regular {@code test} task and
 * only runs via {@code ./gradlew manualTests}, and it requires a DEBUG build.
 */
@Tag("manual")
public class BenchmarkTest extends BaseTest {

    private static final int ITERATIONS = 10;

    public BenchmarkTest() {
        setCardType(JCEd25519.CARD == jcmathlib.OperationSupport.SIMULATOR ? CardType.JCARDSIMLOCAL : CardType.PHYSICAL);
        setSimulateStateful(true);
    }

    @Test
    public void measureOffloadedSigning() throws Exception {
        assumeTrue(JCEd25519.DEBUG, "benchmark reads the private nonce and requires a DEBUG build");

        final CardManager cm = connect();
        final Ed25519Card card = new Ed25519Card(cm);

        try (PrintWriter pw = new PrintWriter(new FileWriter("measurement.csv"))) {
            pw.println("sign_init,sign_nonce,nonce,sign_update,sign_finalize");

            byte[] pub = card.keygen(true);

            for (int j = 0; j < ITERATIONS; ++j) {
                byte[] data = new byte[32];
                for (int i = 0; i < data.length; ++i) {
                    data[i] = (byte) ((0xff & i) + j);
                }

                byte[] signature = signMeasured(cm, card, data, pw);
                assertTrue(Ed25519Card.verify(pub, data, signature));
                pw.flush();
            }
        }
    }

    private byte[] signMeasured(CardManager cm, Ed25519Card card, byte[] data, PrintWriter pw) throws Exception {
        ResponseAPDU r = cm.transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_INIT, 1, 0));
        pw.printf("%d,", cm.getLastTransmitTime());
        assertEquals(Ed25519Card.SW_OK, r.getSW());
        assertEquals(65, r.getData().length);

        byte[] nonce = card.encodeEd25519(card.decodePoint(r.getData()));
        r = cm.transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_NONCE, 0, 0, nonce));
        pw.printf("%d,", cm.getLastTransmitTime());
        assertEquals(Ed25519Card.SW_OK, r.getSW());

        r = cm.transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_GET_PRIV_NONCE, 0, 0));
        assertEquals(Ed25519Card.SW_OK, r.getSW());
        assertEquals(32, r.getData().length);
        for (int i = 0; i < 32; ++i) {
            pw.printf("%02x", r.getData()[i]);
        }
        pw.print(",");

        r = cm.transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_UPDATE, 0, 0, new byte[0]));
        pw.printf("%d,", cm.getLastTransmitTime());
        assertEquals(Ed25519Card.SW_OK, r.getSW());

        r = cm.transmit(new CommandAPDU(Consts.CLA_ED25519, Consts.INS_SIGN_FINALIZE, data.length, 0, data));
        pw.printf("%d\n", cm.getLastTransmitTime());
        assertEquals(Ed25519Card.SW_OK, r.getSW());
        assertEquals(64, r.getData().length);
        return r.getData();
    }
}
