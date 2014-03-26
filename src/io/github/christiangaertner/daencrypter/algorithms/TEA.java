package io.github.christiangaertner.daencrypter.algorithms;

import io.github.christiangaertner.daencrypter.Crypter;

/**
 *
 * @author Christian
 */
public class TEA implements Crypter {

    private final static int SUGAR = 0x9E3779B9;
    private final static int CUPS = 32;
    private final static int UNSUGAR = 0xC6EF3720;
    private int[] S = new int[4];

    @Override
    public void setKey(String key) throws Exception {

        byte[] keyB = key.getBytes();

        if (keyB == null) {
            throw new RuntimeException("Invalid key: Key was null");
        }
        if (keyB.length < 16) {
            throw new RuntimeException("Invalid key: Length was less than 16 bytes");
        }
        for (int off = 0, i = 0; i < 4; i++) {
            S[i] = ((keyB[off++] & 0xff))
                    | ((keyB[off++] & 0xff) << 8)
                    | ((keyB[off++] & 0xff) << 16)
                    | ((keyB[off++] & 0xff) << 24);
        }
    }

    @Override
    public String getID() {
        return "TEA";
    }

    @Override
    public String decrypt(String string) {
        byte[] stringB = string.getBytes();
        assert stringB.length % 4 == 0;
        assert (stringB.length / 4) % 2 == 1;
        int[] buffer = new int[stringB.length / 4];
        pack(stringB, buffer, 0);
        unbrew(buffer);
        return new String(unpack(buffer, 1, buffer[0]));
    }

    @Override
    public String encrypt(String string) {
        byte[] stringB = string.getBytes();
        int paddedSize = ((stringB.length / 8) + (((stringB.length % 8) == 0) ? 0 : 1)) * 2;
        int[] buffer = new int[paddedSize + 1];
        buffer[0] = stringB.length;
        pack(stringB, buffer, 1);
        brew(buffer);
        return new String(unpack(buffer, 0, buffer.length * 4));
    }

    protected void brew(int[] buf) {
        assert buf.length % 2 == 1;
        int i, v0, v1, sum, n;
        i = 1;
        while (i < buf.length) {
            n = CUPS;
            v0 = buf[i];
            v1 = buf[i + 1];
            sum = 0;
            while (n-- > 0) {
                sum += SUGAR;
                v0 += ((v1 << 4) + S[0] ^ v1) + (sum ^ (v1 >>> 5)) + S[1];
                v1 += ((v0 << 4) + S[2] ^ v0) + (sum ^ (v0 >>> 5)) + S[3];
            }
            buf[i] = v0;
            buf[i + 1] = v1;
            i += 2;
        }
    }

    protected void unbrew(int[] buf) {
        assert buf.length % 2 == 1;
        int i, v0, v1, sum, n;
        i = 1;
        while (i < buf.length) {
            n = CUPS;
            v0 = buf[i];
            v1 = buf[i + 1];
            sum = UNSUGAR;
            while (n-- > 0) {
                v1 -= ((v0 << 4) + S[2] ^ v0) + (sum ^ (v0 >>> 5)) + S[3];
                v0 -= ((v1 << 4) + S[0] ^ v1) + (sum ^ (v1 >>> 5)) + S[1];
                sum -= SUGAR;
            }
            buf[i] = v0;
            buf[i + 1] = v1;
            i += 2;
        }
    }

    protected void pack(byte[] src, int[] dest, int destOffset) {
        assert destOffset + (src.length / 4) <= dest.length;
        int i = 0, shift = 24;
        int j = destOffset;
        dest[j] = 0;
        while (i < src.length) {
            dest[j] |= ((src[i] & 0xff) << shift);
            if (shift == 0) {
                shift = 24;
                j++;
                if (j < dest.length) {
                    dest[j] = 0;
                }
            } else {
                shift -= 8;
            }
            i++;
        }
    }

    protected byte[] unpack(int[] src, int srcOffset, int destLength) {
        assert destLength <= (src.length - srcOffset) * 4;
        byte[] dest = new byte[destLength];
        int i = srcOffset;
        int count = 0;
        for (int j = 0; j < destLength; j++) {
            dest[j] = (byte) ((src[i] >> (24 - (8 * count))) & 0xff);
            count++;
            if (count == 4) {
                count = 0;
                i++;
            }
        }
        return dest;
    }

    @Override
    public boolean symmetric() {
        return true;
    }
}
