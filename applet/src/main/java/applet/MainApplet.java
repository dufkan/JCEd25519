package applet;

import javacard.framework.*;
import javacard.security.*;
import applet.jcmathlib.*;

public class MainApplet extends Applet implements MultiSelectable {
	private ECConfig ecc;
	private ECCurve curve;
	private Bignat curveOrder, privateKey, privateNonce, signature;
	private Bignat transformC, transformA3, transformX, transformY;
	private ECPoint publicKey, publicNonce;

	private byte[] masterKey = new byte[32];
	private byte[] prefix = new byte[32];

	private MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);

	private byte[] ramArray = JCSystem.makeTransientByteArray(Wei25519.POINT_SIZE, JCSystem.CLEAR_ON_DESELECT);
	private RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new MainApplet(bArray, bOffset, bLength);
	}

	public MainApplet(byte[] buffer, short offset, byte length) {
	    OperationSupport os = OperationSupport.getInstance();
	    os.setCard(OperationSupport.SIMULATOR);

		ecc = new ECConfig((short) 256);

		curveOrder = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
		privateKey = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
		privateNonce = new Bignat((short) 64, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
		signature = new Bignat((short) 64, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);

		transformC = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
		transformA3 = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
		transformX = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
		transformY = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);

		curveOrder.from_byte_array(Wei25519.r);
		transformC.from_byte_array(Consts.TRANSFORM_C);
		transformA3.from_byte_array(Consts.TRANSFORM_A3);

		curve = new ECCurve(true, Wei25519.p, Wei25519.a, Wei25519.b, Wei25519.G, Wei25519.r, Wei25519.k);
		publicKey = new ECPoint(curve, ecc.ech);
		publicNonce = new ECPoint(curve, ecc.ech);

		register();
	}

	public void process(APDU apdu) {
		if (selectingApplet()) // ignore selection command
			return;

		try {
			if (apdu.getBuffer()[ISO7816.OFFSET_CLA] == Consts.CLA_ED25519) {
				switch (apdu.getBuffer()[ISO7816.OFFSET_INS]) {
					case Consts.INS_KEYGEN:
						generateKeypair(apdu);
						break;
					case Consts.INS_SIGN:
						sign(apdu);
						break;

					default:
						ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
				}
			} else {
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
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
		return true;
	}

	public void deselect(boolean b) {}

	private void generateKeypair(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();

		random.generateData(masterKey, (short) 0, (short) 32);
		hasher.reset();
		hasher.doFinal(masterKey, (short) 0, (short) 32, ramArray, (short) 0);
		ramArray[0] &= (byte) 0xf8; // Clear lowest three bits
		ramArray[31] &= (byte) 0x7f; // Clear highest bit
		ramArray[31] |= (byte) 0x40; // Set second-highest bit
		changeEndianity(ramArray, (short) 0, (short) 32);

		Util.arrayCopyNonAtomic(ramArray, (short) 32, prefix, (short) 0, (short) 32);

		privateKey.from_byte_array((short) 32, (short) 0, ramArray, (short) 0);
		publicKey.setW(curve.G, (short) 0, curve.POINT_SIZE);
		publicKey.multiplication(privateKey);

		encodeEd25519(publicKey, apduBuffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, (short) 32);
	}

	private void sign(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();

		// Generate nonce R
        deterministicNonce(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32);
		// randomNonce();
		publicNonce.setW(Wei25519.G, (short) 0, Wei25519.POINT_SIZE);
		publicNonce.multiplication(privateNonce);

		// Compute challenge e
		hasher.reset();
		encodeEd25519(publicNonce, ramArray, (short) 0);
		hasher.update(ramArray, (short) 0, curve.COORD_SIZE); // R
		encodeEd25519(publicKey, ramArray, (short) 0);
		hasher.update(ramArray, (short) 0, curve.COORD_SIZE); // A
		hasher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, (short) 32, ramArray, (short) 0); // m
		changeEndianity(ramArray, (short) 0, (short) 64);
		signature.set_size((short) 64);
		signature.from_byte_array((short) 64, (short) 0, ramArray, (short) 0);
		signature.mod(curveOrder);
		signature.deep_resize((short) 32);

		// Compute signature s = r + ex
		signature.mod_mult(privateKey, signature, curveOrder);
		signature.mod_add(privateNonce, curveOrder);

		// Return signature (R, s)
		encodeEd25519(publicNonce, apduBuffer, (short) 0);
		signature.prepend_zeros(curve.COORD_SIZE, apduBuffer, curve.COORD_SIZE);
		changeEndianity(apduBuffer, curve.COORD_SIZE, curve.COORD_SIZE);

		apdu.setOutgoingAndSend((short) 0, (short) (curve.COORD_SIZE + curve.COORD_SIZE));
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

	private void deterministicNonce(byte[] msg, short offset, short len) {
		hasher.reset();
		hasher.update(prefix, (short) 0, (short) 32);
		hasher.doFinal(msg, offset, len, ramArray, (short) 0);
		changeEndianity(ramArray, (short) 0, (short) 64);
		privateNonce.set_size((short) 64);
		privateNonce.from_byte_array((short) 64, (short) 0, ramArray, (short) 0);
		privateNonce.mod(curveOrder);
		privateNonce.deep_resize((short) 32);
	}

	private void randomNonce() {
		random.generateData(ramArray, (short) 0,(short) 32);
		privateNonce.set_size((short) 32);
		privateNonce.from_byte_array((short) 32, (short) 0, ramArray, (short) 0);
	}
}
