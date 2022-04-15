package jced25519;

import javacard.security.KeyAgreement;

public class OperationSupport {
    private static OperationSupport instance;

    public static final short SIMULATOR = (short) 0x0000;
    public static final short J2E145G = 0x0001;
    public static final short J3H145 = 0x0002;
    public static final short J3R180 = 0x0003;

    public boolean PRECISE_CURVE_BITLENGTH = true;
    public boolean RSA_MULT_TRICK = false;
    public boolean RSA_MOD_EXP = true;
    public boolean RSA_PREPEND_ZEROS = false;
    public boolean RSA_KEY_REFRESH = false;
    public boolean ECDH_X_ONLY = true;
    public boolean ECDH_XY = false;
    public boolean COFACTOR = false;

    private OperationSupport() {}

    public static OperationSupport getInstance() {
        if (OperationSupport.instance == null)
            OperationSupport.instance = new OperationSupport();
        return OperationSupport.instance;
    }

    public void setCard(short card_identifier) {
        switch (card_identifier) {
            case SIMULATOR:
                PRECISE_CURVE_BITLENGTH = false;
                RSA_MULT_TRICK = false;
                RSA_PREPEND_ZEROS = true;
                RSA_KEY_REFRESH = true;
                ECDH_XY = true;
                break;
            case J2E145G:
                RSA_MULT_TRICK = true;
                break;
            case J3H145:
                RSA_MOD_EXP = false;
                ECDH_XY = true;
                break;
            case J3R180:
                RSA_MULT_TRICK = true;
                RSA_MOD_EXP = false;
                ECDH_XY = true;
                break;
            default:
                break;
        }
    }

    public void setAutomatically() {
        ECDH_XY = testECDHXY();
        ECDH_X_ONLY = testECDHX();
    }

    private boolean testECDHXY() {
        try {
            KeyAgreement.getInstance(jcmathlib.ECPoint_Helper.ALG_EC_SVDP_DH_PLAIN_XY, false);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean testECDHX() {
        try {
            KeyAgreement.getInstance(jcmathlib.ECPoint_Helper.ALG_EC_SVDP_DH_PLAIN, false);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
