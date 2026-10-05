package com.github.bucchi.dbsc.verification;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class EcdsaSignatureEncodingTest {

    @Test
    void convertsTpmIntegersToDerAndAddsPositiveSignPadding() {
        byte[] der = EcdsaSignatureEncoding.tpmToDer(
                new byte[]{(byte) 0x80},
                new byte[]{0x01});

        assertArrayEquals(new byte[]{0x30, 0x07, 0x02, 0x02, 0x00, (byte) 0x80, 0x02, 0x01, 0x01}, der);
    }

    @Test
    void convertsJoseP1363SignatureToDer() {
        byte[] jose = new byte[64];
        jose[31] = (byte) 0x80;
        jose[63] = 0x01;

        byte[] der = EcdsaSignatureEncoding.joseToDer(jose);

        assertArrayEquals(new byte[]{0x30, 0x07, 0x02, 0x02, 0x00, (byte) 0x80, 0x02, 0x01, 0x01}, der);
    }

    @Test
    void rejectsInvalidJoseSignatureLength() {
        assertThrows(SecurityException.class,
                () -> EcdsaSignatureEncoding.joseToDer(new byte[63]));
    }

    @Test
    void rejectsEmptyTpmSignatureComponents() {
        assertThrows(SecurityException.class,
                () -> EcdsaSignatureEncoding.tpmToDer(new byte[0], new byte[]{0x01}));
    }
}