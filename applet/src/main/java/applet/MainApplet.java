package applet;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.RandomData;
import applet.jcmathlib.*;

public class MainApplet extends Applet implements MultiSelectable
{
	private static final short BUFFER_SIZE = 65;
	public ECConfig ecc = new ECConfig((short) 256);
	public ECCurve curve = new ECCurve(true, Wei25519.p, Wei25519.a, Wei25519.b, Wei25519.G, Wei25519.r, Wei25519.k);

	public Bignat privateKey = new Bignat(SecP256r1.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
	public ECPoint publicKey = new ECPoint(curve, ecc.ech);



	private byte[] ramArray = JCSystem.makeTransientByteArray(BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
	private RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new MainApplet(bArray, bOffset, bLength);
	}
	
	public MainApplet(byte[] buffer, short offset, byte length)
	{
		ecc.bnh.bIsSimulator = true;

		register();
	}

	public void process(APDU apdu)
	{
		if (selectingApplet()) // ignore selection command
			return;

		try {
			if(apdu.getBuffer()[ISO7816.OFFSET_CLA] == Consts.CLA_ED25519) {
				switch(apdu.getBuffer()[ISO7816.OFFSET_INS]) {
					case Consts.INS_KEYGEN:
						generateKeypair(apdu);
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

		random.generateData(ramArray, (short) 0, (short) 32);

		privateKey.set_from_byte_array((short) 0, ramArray, (short) 0, (short) 32);
		publicKey.setW(Wei25519.G, (short) 0, Wei25519.POINT_SIZE);
		publicKey.multiplication(privateKey);

		publicKey.getW(apduBuffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, Wei25519.POINT_SIZE);
	}
}
