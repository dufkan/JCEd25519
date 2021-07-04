package applet;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import applet.jcmathlib.*;

public class MainApplet extends Applet implements MultiSelectable {
	public static final byte[] TRANSFORM_C = {
			(byte) 0x70, (byte) 0xd9, (byte) 0x12, (byte) 0x0b,
			(byte) 0x9f, (byte) 0x5f, (byte) 0xf9, (byte) 0x44,
			(byte) 0x2d, (byte) 0x84, (byte) 0xf7, (byte) 0x23,
			(byte) 0xfc, (byte) 0x03, (byte) 0xb0, (byte) 0x81,
			(byte) 0x3a, (byte) 0x5e, (byte) 0x2c, (byte) 0x2e,
			(byte) 0xb4, (byte) 0x82, (byte) 0xe5, (byte) 0x7d,
			(byte) 0x33, (byte) 0x91, (byte) 0xfb, (byte) 0x55,
			(byte) 0x00, (byte) 0xba, (byte) 0x81, (byte) 0xe7
	};
	public static final byte[] TRANSFORM_A3 = {
			(byte) 0x2a, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
			(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
			(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
			(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
			(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
			(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
			(byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
			(byte) 0xaa, (byte) 0xad, (byte) 0x24, (byte) 0x51
	};

	public ECConfig ecc = new ECConfig((short) 256);
	public ECCurve curve = new ECCurve(true, Wei25519.p, Wei25519.a, Wei25519.b, Wei25519.G, Wei25519.r, Wei25519.k);
	public Bignat curveOrder = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);

	private byte[] masterKey = new byte[32];
	private byte[] prefix = new byte[32];
	public Bignat privateKey = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
	public ECPoint publicKey = new ECPoint(curve, ecc.ech);

	public Bignat privateNonce = new Bignat((short) 64, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
	public ECPoint publicNonce = new ECPoint(curve, ecc.ech);

	public Bignat signature = new Bignat((short) 64, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);

	public Bignat transformC = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
	public Bignat transformA3 = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
	public Bignat transformX = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
	public Bignat transformY = new Bignat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);

	public MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);

	private byte[] ramArray = JCSystem.makeTransientByteArray(Wei25519.POINT_SIZE, JCSystem.CLEAR_ON_DESELECT);
	private RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new MainApplet(bArray, bOffset, bLength);
	}

	public MainApplet(byte[] buffer, short offset, byte length) {
		ecc.bnh.bIsSimulator = true;

		curveOrder.from_byte_array(Wei25519.r);
		transformC.from_byte_array(TRANSFORM_C);
		transformA3.from_byte_array(TRANSFORM_A3);

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
		signature.shrink();

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
		transformX.from_byte_array((short) 32, (short) 0, ramArray, (short) 1);
		transformY.from_byte_array((short) 32, (short) 0, ramArray, (short) 33);
		transformX.mod_sub(transformA3, curve.pBN);
		transformX.mod_mult(transformX, transformC, curve.pBN);
		transformY.mod_inv(curve.pBN);
		transformX.mod_mult(transformX, transformY, curve.pBN);

		boolean x_bit = transformX.is_odd();

		// Compute Y
		transformX.from_byte_array((short) 32, (short) 0, ramArray, (short) 1);
		transformX.mod_sub(transformA3, curve.pBN);
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
		privateNonce.shrink();
	}

	private void randomNonce() {
		random.generateData(ramArray, (short) 0,(short) 32);
		privateNonce.set_size((short) 32);
		privateNonce.from_byte_array((short) 32, (short) 0, ramArray, (short) 0);
	}
}
