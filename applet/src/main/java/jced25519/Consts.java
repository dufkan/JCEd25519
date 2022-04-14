/*
JCEd25519 is an applet for creating Ed25519 signatures using JC API.
Copyright (C) 2021 Antonín Dufka

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package jced25519;

public class Consts {
    public static final byte CLA_ED25519 = (byte) 0x00;
    public static final byte INS_INITIALIZE = (byte) 0xDF;
    public static final byte INS_KEYGEN = (byte) 0xD0;
    public static final byte INS_GET_PRIV = (byte) 0xD2;
    public static final byte INS_SET_PUB = (byte) 0xD3;
    public static final byte INS_SIGN_INIT = (byte) 0xD4;
    public static final byte INS_SIGN_NONCE = (byte) 0xD5;
    public static final byte INS_SIGN_FINALIZE = (byte) 0xD6;
    public static final byte INS_SIGN_UPDATE = (byte) 0xD7;
    public static final byte INS_GET_PRIV_NONCE = (byte) 0xD8;

    public final static short E_ALREADY_INITIALIZED = (short) 0xee00;
    public final static short E_UNINITIALIZED = (short) 0xee01;
    public final static short E_DEBUG_DISABLED = (short) 0xee02;

    public final static short SW_Exception = (short) 0xff01;
    public final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    public final static short SW_ArithmeticException = (short) 0xff03;
    public final static short SW_ArrayStoreException = (short) 0xff04;
    public final static short SW_NullPointerException = (short) 0xff05;
    public final static short SW_NegativeArraySizeException = (short) 0xff06;
    public final static short SW_CryptoException_prefix = (short) 0xf100;
    public final static short SW_SystemException_prefix = (short) 0xf200;
    public final static short SW_PINException_prefix = (short) 0xf300;
    public final static short SW_TransactionException_prefix = (short) 0xf400;
    public final static short SW_CardRuntimeException_prefix = (short) 0xf500;

    public final static byte[] TRANSFORM_C = {
            (byte) 0x70, (byte) 0xd9, (byte) 0x12, (byte) 0x0b,
            (byte) 0x9f, (byte) 0x5f, (byte) 0xf9, (byte) 0x44,
            (byte) 0x2d, (byte) 0x84, (byte) 0xf7, (byte) 0x23,
            (byte) 0xfc, (byte) 0x03, (byte) 0xb0, (byte) 0x81,
            (byte) 0x3a, (byte) 0x5e, (byte) 0x2c, (byte) 0x2e,
            (byte) 0xb4, (byte) 0x82, (byte) 0xe5, (byte) 0x7d,
            (byte) 0x33, (byte) 0x91, (byte) 0xfb, (byte) 0x55,
            (byte) 0x00, (byte) 0xba, (byte) 0x81, (byte) 0xe7
    };
    public final static byte[] TRANSFORM_A3 = {
            (byte) 0x2a, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xaa, (byte) 0xaa, (byte) 0xaa,
            (byte) 0xaa, (byte) 0xad, (byte) 0x24, (byte) 0x51
    };
    public final static byte[] EIGHT = {
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x08
    };
}
