package jced25519;

import javacard.framework.*;
import javacard.security.*;
import jced25519.jcmathlib.*;
import jced25519.swalgs.*;

public class JCEd25519 extends Applet implements MultiSelectable {
    private final boolean DEBUG = true;

    private ECConfig ecc;
    private ECCurve curve;
    private Bignat privateKey, privateNonce, signature;
    private Bignat transformC, transformA3, transformX, transformY, eight;
    private ECPoint point;

    private final byte[] masterKey = new byte[32];
    private final byte[] prefix = new byte[32];
    private final byte[] publicKey = new byte[32];
    private final byte[] publicNonce = new byte[32];

    private MessageDigest hasher;

    private final byte[] ramArray = JCSystem.makeTransientByteArray(Wei25519.POINT_SIZE, JCSystem.CLEAR_ON_DESELECT);
    private final RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

    private boolean initialized = false;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JCEd25519(bArray, bOffset, bLength);
    }

    public JCEd25519(byte[] buffer, short offset, byte length) {
        OperationSupport.getInstance().setCard(OperationSupport.SIMULATOR);
        register();
    }

    public void process(APDU apdu) {
        if (selectingApplet())
            return;

        if (apdu.getBuffer()[ISO7816.OFFSET_CLA] != Consts.CLA_ED25519)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        try {
            switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
                case Consts.INS_INITIALIZE:
                    initialize(apdu);
                    break;

                case Consts.INS_KEYGEN:
                    generateKeypair(apdu);
                    break;

                case Consts.INS_SET_PUB:
                    setPublicKey(apdu);
                    break;
                case Consts.INS_SIGN_INIT:
                    signInit(apdu);
                    break;
                case Consts.INS_SIGN_NONCE:
                    signNonce(apdu);
                    break;
                case Consts.INS_SIGN_FINALIZE:
                    signFinalize(apdu);
                    break;
                case Consts.INS_SIGN_UPDATE:
                    signUpdate(apdu);
                    break;

                case Consts.INS_GET_PRIV:
                    if(!DEBUG) {
                        ISOException.throwIt(Consts.E_DEBUG_DISABLED);
                    }
                    Util.arrayCopyNonAtomic(privateKey.as_byte_array(), (short) 0, apdu.getBuffer(), (short) 0, (short) 32);
                    apdu.setOutgoingAndSend((short) 0, (short) 32);
                    break;
                case Consts.INS_GET_PRIV_NONCE:
                    if(!DEBUG) {
                        ISOException.throwIt(Consts.E_DEBUG_DISABLED);
                    }
                    Util.arrayCopyNonAtomic(privateNonce.as_byte_array(), (short) 0, apdu.getBuffer(), (short) 0, (short) 32);
                    apdu.setOutgoingAndSend((short) 0, (short) 32);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(Consts.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(Consts.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Consts.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(Consts.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Consts.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (Consts.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (Consts.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (Consts.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (Consts.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (Consts.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Consts.SW_Exception);
        }
    }

    public boolean select(boolean b) {
        ecc.refreshAfterReset();
        return true;
    }

    public void deselect(boolean b) {}

    private void initialize(APDU apdu) {
        if (initialized)
            ISOException.throwIt(Consts.E_ALREADY_INITIALIZED);

        try {
            hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        } catch (CryptoException e) {
            hasher = new Sha2(Sha2.SHA_512);
        }

        ecc = new ECConfig((short) 256);

        privateKey = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);

        privateNonce = new Bignat((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.bnh);
        signature = new Bignat((short) 64, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, ecc.bnh);

        transformC = new Bignat(Consts.TRANSFORM_C, null);
        transformA3 = new Bignat(Consts.TRANSFORM_A3, null);
        transformX = new Bignat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, ecc.bnh);
        transformY = new Bignat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, ecc.bnh);

        eight = new Bignat(Consts.EIGHT, null);

        curve = new ECCurve(false, Wei25519.p, Wei25519.a, Wei25519.b, Wei25519.G, Wei25519.r, Wei25519.k);
        point = new ECPoint(curve, ecc.ech);

        initialized = true;
    }

    private void generateKeypair(APDU apdu) {
        if (!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        boolean offload = apduBuffer[ISO7816.OFFSET_P1] != (byte) 0x00;

        random.generateData(masterKey, (short) 0, (short) 32);
        hasher.reset();
        hasher.doFinal(masterKey, (short) 0, (short) 32, ramArray, (short) 0);
        ramArray[0] &= (byte) 0xf8; // Clear lowest three bits
        ramArray[31] &= (byte) 0x7f; // Clear highest bit
        ramArray[31] |= (byte) 0x40; // Set second-highest bit
        changeEndianity(ramArray, (short) 0, (short) 32);

        Util.arrayCopyNonAtomic(ramArray, (short) 32, prefix, (short) 0, (short) 32);

        privateKey.from_byte_array((short) 32, (short) 0, ramArray, (short) 0);
        privateKey.shift_bits_right_3(); // Required by smartcards (scalar must be lesser than r)
        point.setW(curve.G, (short) 0, curve.POINT_SIZE);
        point.multiplication(privateKey);
        privateKey.from_byte_array((short) 32, (short) 0, ramArray, (short) 0); // Reload private key

        if(!offload) {
            point.multiplication(eight); // Compensate bit shift

            encodeEd25519(point, publicKey, (short) 0);

            Util.arrayCopyNonAtomic(publicKey, (short) 0, apduBuffer, (short) 0, (short) 32);
            apdu.setOutgoingAndSend((short) 0, (short) 32);
        } else {
            point.getW(apduBuffer, (short) 0);
            apdu.setOutgoingAndSend((short) 0, curve.POINT_SIZE);
        }
    }

    private void setPublicKey(APDU apdu) {
        if (!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, publicKey, (short) 0, (short) publicKey.length);
        apdu.setOutgoing();
    }

    private void signInit(APDU apdu) {
        if (!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        boolean offload = apduBuffer[ISO7816.OFFSET_P1] != (byte) 0x00;

        // Generate nonce R
        randomNonce();
        point.setW(curve.G, (short) 0, curve.POINT_SIZE);
        point.multiplication(privateNonce);
        hasher.reset();
        if (offload) {
            point.getW(apduBuffer, (short) 0);
            apdu.setOutgoingAndSend((short) 0, curve.POINT_SIZE);
        } else {
            encodeEd25519(point, ramArray, (short) 0);
            Util.arrayCopyNonAtomic(ramArray, (short) 0, publicNonce, (short) 0, curve.COORD_SIZE);
            hasher.update(ramArray, (short) 0, curve.COORD_SIZE); // R
            hasher.update(publicKey, (short) 0, curve.COORD_SIZE); // A
            apdu.setOutgoing();
        }
    }

    private void signNonce(APDU apdu) {
        if (!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        hasher.reset();
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, publicNonce, (short) 0, curve.COORD_SIZE);
        hasher.update(apduBuffer, ISO7816.OFFSET_CDATA, curve.COORD_SIZE); // R
        hasher.update(publicKey, (short) 0, curve.COORD_SIZE); // A
        apdu.setOutgoing();
    }

    private void signFinalize(APDU apdu) {
        if (!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        short len = (short) ((short) apduBuffer[ISO7816.OFFSET_P1] & (short) 0xff);
        hasher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, len, apduBuffer, (short) 0); // m
        changeEndianity(apduBuffer, (short) 0, (short) 64);
        signature.set_size((short) 64);
        signature.from_byte_array((short) 64, (short) 0, apduBuffer, (short) 0);
        signature.mod(curve.rBN);
        signature.deep_resize((short) 32);

        // Compute signature s = r + ex
        signature.mod_mult(privateKey, signature, curve.rBN);
        signature.mod_add(privateNonce, curve.rBN);

        // Return signature (R, s)
        Util.arrayCopyNonAtomic(publicNonce, (short) 0, apduBuffer, (short) 0, curve.COORD_SIZE);
        signature.prepend_zeros(curve.COORD_SIZE, apduBuffer, curve.COORD_SIZE);
        changeEndianity(apduBuffer, curve.COORD_SIZE, curve.COORD_SIZE);
        apdu.setOutgoingAndSend((short) 0, (short) (curve.COORD_SIZE + curve.COORD_SIZE));
    }

    private void signUpdate(APDU apdu) {
        if (!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        short len = (short) ((short) apduBuffer[ISO7816.OFFSET_P1] & (short) 0xff);
        hasher.update(apduBuffer, ISO7816.OFFSET_CDATA, len);
        apdu.setOutgoing();
    }

    private void encodeEd25519(ECPoint point, byte[] buffer, short offset) {
        point.getW(ramArray, (short) 0);

        // Compute X
        transformX.set_size((short) 32);
        transformX.from_byte_array((short) 32, (short) 0, ramArray, (short) 1);
        transformY.set_size((short) 32);
        transformY.from_byte_array((short) 32, (short) 0, ramArray, (short) 33);
        transformX.mod_sub(transformA3, curve.pBN);
        transformX.mod_mult(transformX, transformC, curve.pBN);
        transformY.mod_inv(curve.pBN);
        transformX.mod_mult(transformX, transformY, curve.pBN);
        transformX.deep_resize((short) 32);

        boolean x_bit = transformX.is_odd();

        // Compute Y
        transformX.from_byte_array((short) 32, (short) 0, ramArray, (short) 1);
        transformX.mod_sub(transformA3, curve.pBN);
        transformY.set_size((short) 32);
        transformY.copy(transformX);
        transformX.decrement_one();
        transformY.mod_add(Bignat_Helper.ONE, curve.pBN);
        transformY.mod_inv(curve.pBN);
        transformX.mod_mult(transformX, transformY, curve.pBN);
        transformX.prepend_zeros(curve.COORD_SIZE, buffer, offset);

        buffer[offset] |= x_bit ? (byte) 0x80 : (byte) 0x00;

        changeEndianity(buffer, offset, (short) 32);
    }

    private void changeEndianity(byte[] array, short offset, short len) {
        for (short i = 0; i < (short) (len / 2); ++i) {
            byte tmp = array[(short) (offset + len - i - 1)];
            array[(short) (offset + len - i - 1)] = array[(short) (offset + i)];
            array[(short) (offset + i)] = tmp;
        }
    }

    // CAN BE USED ONLY IF NO OFFLOADING IS USED; OTHERWISE INSECURE!
    private void deterministicNonce(byte[] msg, short offset, short len) {
        hasher.reset();
        hasher.update(prefix, (short) 0, (short) 32);
        hasher.doFinal(msg, offset, len, ramArray, (short) 0);
        changeEndianity(ramArray, (short) 0, (short) 64);
        privateNonce.set_size((short) 64);
        privateNonce.from_byte_array((short) 64, (short) 0, ramArray, (short) 0);
        privateNonce.mod(curve.rBN);
        privateNonce.deep_resize((short) 32);
    }

    private void randomNonce() {
        random.generateData(ramArray, (short) 0, (short) 32);
        privateNonce.from_byte_array((short) 32, (short) 0, ramArray, (short) 0);
        privateNonce.mod(curve.rBN);
        privateNonce.deep_resize((short) 32);
    }
}
