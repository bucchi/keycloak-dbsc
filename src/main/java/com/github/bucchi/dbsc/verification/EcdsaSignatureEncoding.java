package com.github.bucchi.dbsc.verification;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

final class EcdsaSignatureEncoding {

    private EcdsaSignatureEncoding() {
    }

    static byte[] joseToDer(byte[] signature) {
        if (signature == null || signature.length != 64) {
            throw new SecurityException("ES256 JWS署名は64バイトである必要があります。");
        }
        return toDer(Arrays.copyOfRange(signature, 0, 32), Arrays.copyOfRange(signature, 32, 64));
    }

    static byte[] tpmToDer(byte[] r, byte[] s) {
        if (r == null || r.length == 0 || s == null || s.length == 0) {
            throw new SecurityException("TPMT_SIGNATUREのECDSA成分が空です。");
        }
        return toDer(r, s);
    }

    private static byte[] toDer(byte[] r, byte[] s) {
        ByteArrayOutputStream content = new ByteArrayOutputStream();
        writeInteger(content, r);
        writeInteger(content, s);

        byte[] sequenceContent = content.toByteArray();
        ByteArrayOutputStream sequence = new ByteArrayOutputStream();
        sequence.write(0x30);
        writeLength(sequence, sequenceContent.length);
        sequence.writeBytes(sequenceContent);
        return sequence.toByteArray();
    }

    private static void writeInteger(ByteArrayOutputStream output, byte[] value) {
        int first = 0;
        while (first < value.length - 1 && value[first] == 0) {
            first++;
        }
        boolean needsPadding = (value[first] & 0x80) != 0;

        output.write(0x02);
        writeLength(output, value.length - first + (needsPadding ? 1 : 0));
        if (needsPadding) {
            output.write(0);
        }
        output.write(value, first, value.length - first);
    }

    private static void writeLength(ByteArrayOutputStream output, int length) {
        if (length < 0x80) {
            output.write(length);
            return;
        }
        int byteCount = 0;
        for (int remaining = length; remaining > 0; remaining >>>= 8) {
            byteCount++;
        }
        output.write(0x80 | byteCount);
        for (int shift = (byteCount - 1) * 8; shift >= 0; shift -= 8) {
            output.write(length >>> shift);
        }
    }
}