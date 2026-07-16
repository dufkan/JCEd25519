package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import jced25519.Consts;
import jced25519.JCEd25519;
import jced25519.jcmathlib;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Functional and error-path tests for the JCEd25519 applet.
 *
 * These tests exercise both the on-card ("non-offload") and host-assisted
 * ("offload") code paths and validate produced signatures against the reference
 * {@code net.i2p.crypto.eddsa} implementation.
 */
public class AppletTest extends BaseTest {

    public AppletTest() {
        setCardType(JCEd25519.CARD == jcmathlib.OperationSupport.SIMULATOR ? CardType.JCARDSIMLOCAL : CardType.PHYSICAL);
        setSimulateStateful(true);
    }

    private Ed25519Card card() throws Exception {
        return new Ed25519Card(connect());
    }

    // ------------------------------------------------------------------
    // Correctness: key generation and signing
    // ------------------------------------------------------------------

    @Test
    @DisplayName("Non-offload keygen produces a key that verifies signatures")
    public void keygenAndSign_nonOffload() throws Exception {
        Ed25519Card card = card();
        byte[] pub = card.keygen(false);

        byte[] msg = message(32, 0);
        byte[] sig = card.sign(msg, false);

        assertTrue(Ed25519Card.verify(pub, msg, sig));
    }

    @Test
    @DisplayName("Offload keygen produces a key that verifies signatures")
    public void keygenAndSign_offload() throws Exception {
        Ed25519Card card = card();
        byte[] pub = card.keygen(true);

        byte[] msg = message(32, 0);
        byte[] sig = card.sign(msg, true);

        assertTrue(Ed25519Card.verify(pub, msg, sig));
    }

    @Test
    @DisplayName("Offload keygen and non-offload signing interoperate")
    public void keygenOffload_signNonOffload() throws Exception {
        Ed25519Card card = card();
        byte[] pub = card.keygen(true);

        byte[] msg = message(48, 7);
        byte[] sig = card.sign(msg, false);

        assertTrue(Ed25519Card.verify(pub, msg, sig));
    }

    @Test
    @DisplayName("Empty message can be signed and verified")
    public void signEmptyMessage() throws Exception {
        Ed25519Card card = card();
        byte[] pub = card.keygen(false);

        byte[] sig = card.sign(new byte[0], false);

        assertTrue(Ed25519Card.verify(pub, new byte[0], sig));
    }

    @Test
    @DisplayName("Message longer than one APDU is signed via INS_SIGN_UPDATE")
    public void signChunkedMessage() throws Exception {
        Ed25519Card card = card();
        byte[] pub = card.keygen(false);

        byte[] msg = message(200, 3);
        byte[] sig = card.signChunked(msg, false, 64);

        assertTrue(Ed25519Card.verify(pub, msg, sig));
    }

    @Test
    @DisplayName("Chunked and single-shot signing produce equally valid signatures")
    public void chunkedMatchesSingleShot() throws Exception {
        Ed25519Card card = card();
        byte[] pub = card.keygen(true);

        byte[] msg = message(100, 9);
        byte[] chunked = card.signChunked(msg, true, 30);
        byte[] single = card.sign(msg, true);

        assertTrue(Ed25519Card.verify(pub, msg, chunked));
        assertTrue(Ed25519Card.verify(pub, msg, single));
    }

    @Test
    @DisplayName("Repeated signatures use a fresh random nonce and all verify")
    public void repeatedSignaturesUseFreshNonce() throws Exception {
        Ed25519Card card = card();
        byte[] pub = card.keygen(false);

        byte[] msg = message(32, 1);
        byte[] sig1 = card.sign(msg, false);
        byte[] sig2 = card.sign(msg, false);

        assertTrue(Ed25519Card.verify(pub, msg, sig1));
        assertTrue(Ed25519Card.verify(pub, msg, sig2));
        // Same message, but a random nonce means R (and therefore the signature) differs.
        assertNotEquals(toHex(sig1), toHex(sig2), "signatures of the same message must not be identical");
    }

    @Test
    @DisplayName("Signature does not verify against a different message")
    public void signatureRejectsWrongMessage() throws Exception {
        Ed25519Card card = card();
        byte[] pub = card.keygen(false);

        byte[] msg = message(32, 0);
        byte[] sig = card.sign(msg, false);

        byte[] tampered = msg.clone();
        tampered[0] ^= 0x01;
        assertFalse(Ed25519Card.verify(pub, tampered, sig));
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    private static byte[] message(int len, int seed) {
        byte[] data = new byte[len];
        for (int i = 0; i < len; ++i) {
            data[i] = (byte) ((0xff & i) + seed);
        }
        return data;
    }

    private static String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16));
            sb.append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString();
    }
}
