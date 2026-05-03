import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JBASC {

    static final int WORDS      = 8;
    static final int ROUNDS     = 10;
    static final int BLOCK_SIZE = 64;
    static final int IV_SIZE    = BLOCK_SIZE
    static final int MAC_SIZE   = 32;

    static int gfMul(int a, int b) {
        int r = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) r ^= a;
            boolean hi = (a & 0x80) != 0;
            a = (a << 1) & 0xFF;
            if (hi) a ^= 0x1B;
            b >>= 1;
        }
        return r & 0xFF;
    }

    static final int[][] GF_MUL = buildGfMulTable();
    static int[][] buildGfMulTable() {
        int[][] t = new int[256][256];
        for (int a = 0; a < 256; a++)
            for (int b = 0; b < 256; b++)
                t[a][b] = gfMul(a, b);
        return t;
    }

    static final int[] GF_INV = buildGfInvTable();
    static int[] buildGfInvTable() {
        int[] t = new int[256];
        for (int i = 1; i < 256; i++)
            for (int j = 1; j < 256; j++)
                if (GF_MUL[i][j] == 1) { t[i] = j; break; }
        return t;
    }

    static int gf2MatVecMul(int[] M, int v) {
        int result = 0;
        for (int i = 0; i < 8; i++) {
            int dot = Integer.bitCount(M[i] & v) & 1;
            result |= (dot << (7 - i));
        }
        return result;
    }

    static int[] gf2MatInverse(int[] M) {
        int[] aug = new int[8];
        for (int i = 0; i < 8; i++) aug[i] = M[i] | ((0x80 >> i) << 8);
        int pivot = 0;
        for (int col = 7; col >= 0; col--) {
            int found = -1;
            for (int row = pivot; row < 8; row++)
                if (((aug[row] >> col) & 1) == 1) { found = row; break; }
            if (found == -1) throw new ArithmeticException("Singular matrix");
            int tmp = aug[pivot]; aug[pivot] = aug[found]; aug[found] = tmp;
            for (int row = 0; row < 8; row++)
                if (row != pivot && ((aug[row] >> col) & 1) == 1)
                    aug[row] ^= aug[pivot];
            pivot++;
        }
        int[] inv = new int[8];
        for (int i = 0; i < 8; i++) inv[i] = (aug[i] >> 8) & 0xFF;
        return inv;
    }

    static byte[] sha256(byte[]... in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] b : in) md.update(b);
            return md.digest();
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static byte[] expand(byte[] k, byte[] s, byte[] label, int n) {
        byte[] out = new byte[n];
        int p = 0, i = 0;
        while (p < n) {
            byte[] h = sha256(k, s, label, new byte[]{(byte)(i >> 8), (byte)i});
            i++;
            int c = Math.min(h.length, n - p);
            System.arraycopy(h, 0, out, p, c);
            p += c;
        }
        return out;
    }
    static long[] bytesToState(byte[] b) {
        if (b.length < BLOCK_SIZE) throw new IllegalArgumentException("Need 64 bytes");
        long[] s = new long[WORDS];
        for (int i = 0; i < WORDS; i++) {
            long v = 0;
            for (int j = 0; j < 8; j++) v = (v << 8) | (b[i * 8 + j] & 0xFFL);
            s[i] = v;
        }
        return s;
    }

    static byte[] stateToBytes(long[] s) {
        byte[] b = new byte[BLOCK_SIZE];
        for (int i = 0; i < WORDS; i++) {
            long v = s[i];
            for (int j = 7; j >= 0; j--) { b[i * 8 + j] = (byte)(v & 0xFF); v >>= 8; }
        }
        return b;
    }

    static long bytesToLong8(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[off + i] & 0xFFL);
        return v;
    }


    static final int[] MDS8_X = {1, 2, 3, 4, 5, 6, 7, 8};
    static final int[] MDS8_Y = {9,10,11,12,13,14,15,16};

    static final int[][] MDS8     = buildMds8();
    static final int[][] MDS8_INV = gf28MatInverse(MDS8);

    static int[][] buildMds8() {
        int[][] M = new int[8][8];
        for (int i = 0; i < 8; i++)
            for (int j = 0; j < 8; j++)
                M[i][j] = GF_INV[MDS8_X[i] ^ MDS8_Y[j]]; // 1/(x_i + y_j)
        return M;
    }

    static int[] gf28MatVecMul(int[][] M, int[] v) {
        int[] out = new int[8];
        for (int i = 0; i < 8; i++) {
            int acc = 0;
            for (int j = 0; j < 8; j++) acc ^= GF_MUL[M[i][j]][v[j]];
            out[i] = acc;
        }
        return out;
    }

    static int[][] gf28MatInverse(int[][] M) {
        int[][] aug = new int[8][16];
        for (int i = 0; i < 8; i++) {
            System.arraycopy(M[i], 0, aug[i], 0, 8);
            aug[i][8 + i] = 1;
        }
        for (int col = 0; col < 8; col++) {
            int pivot = -1;
            for (int row = col; row < 8; row++)
                if (aug[row][col] != 0) { pivot = row; break; }
            if (pivot == -1) throw new ArithmeticException("Singular MDS matrix");
            int[] tmp = aug[col]; aug[col] = aug[pivot]; aug[pivot] = tmp;
            int scale = GF_INV[aug[col][col]];
            for (int j = 0; j < 16; j++) aug[col][j] = GF_MUL[aug[col][j]][scale];
            for (int row = 0; row < 8; row++) {
                if (row == col || aug[row][col] == 0) continue;
                int factor = aug[row][col];
                for (int j = 0; j < 16; j++)
                    aug[row][j] ^= GF_MUL[factor][aug[col][j]];
            }
        }
        int[][] inv = new int[8][8];
        for (int i = 0; i < 8; i++)
            System.arraycopy(aug[i], 8, inv[i], 0, 8);
        return inv;
    }

    static void mixWords(long[] st, boolean inverse) {
        int[][] M = inverse ? MDS8_INV : MDS8;
        for (int lane = 0; lane < 8; lane++) {
            int shift = 56 - lane * 8;
            int[] col = new int[8];
            for (int i = 0; i < 8; i++)
                col[i] = (int)((st[i] >>> shift) & 0xFF);
            int[] mixed = gf28MatVecMul(M, col);
            for (int i = 0; i < 8; i++) {
                long mask = ~(0xFFL << shift);
                st[i] = (st[i] & mask) | ((long)(mixed[i] & 0xFF) << shift);
            }
        }
    }
    static class KeySchedule {
        long[][]   roundKeys;
        int[][][]  sbox;
        int[][][]  sboxInv;
        byte[]     macKey;

        KeySchedule() {
            roundKeys = new long[ROUNDS][WORDS];
            sbox      = new int[ROUNDS][WORDS][256];
            sboxInv   = new int[ROUNDS][WORDS][256];
        }
    }

    static KeySchedule build(byte[] k, byte[] s) {
        KeySchedule ks = new KeySchedule();

        byte[] cipherKey = sha256(k, s, "CIPHER".getBytes());
        byte[] macKey    = sha256(k, s, "MAC".getBytes());
        ks.macKey = macKey;

        byte[] rk = expand(cipherKey, s, "RK".getBytes(), ROUNDS * WORDS * 8);
        for (int r = 0; r < ROUNDS; r++)
            for (int i = 0; i < WORDS; i++)
                ks.roundKeys[r][i] = bytesToLong8(rk, (r * WORDS + i) * 8);
        byte[] sboxSeed = expand(cipherKey, s, "SBOX".getBytes(), ROUNDS * WORDS * 9);
        int seedOff = 0;

        for (int r = 0; r < ROUNDS; r++) {
            for (int w = 0; w < WORDS; w++) {
                int[] seedBytes = new int[8];
                for (int i = 0; i < 8; i++) seedBytes[i] = sboxSeed[seedOff + i] & 0xFF;
                seedOff += 8;
                int c = sboxSeed[seedOff++] & 0xFF;
                int[] L = new int[8];
                for (int i = 0; i < 8; i++) L[i] = 1 << (7 - i); // diagonal
                int bitSrc = (seedBytes[0] << 24) | (seedBytes[1] << 16)
                           | (seedBytes[2] <<  8) |  seedBytes[3];
                int bitPos = 0;
                for (int i = 1; i < 8; i++)
                    for (int j = 0; j < i; j++) {
                        if (((bitSrc >>> (31 - bitPos)) & 1) == 1)
                            L[i] |= (1 << (7 - j));
                        bitPos++;
                    }

                int[] U = new int[8];
                for (int i = 0; i < 8; i++) U[i] = 1 << (7 - i); // diagonal
                bitSrc = (seedBytes[4] << 24) | (seedBytes[5] << 16)
                       | (seedBytes[6] <<  8) |  seedBytes[7];
                bitPos = 0;
                for (int i = 0; i < 7; i++)
                    for (int j = i + 1; j < 8; j++) {
                        if (((bitSrc >>> (31 - bitPos)) & 1) == 1)
                            U[i] |= (1 << (7 - j));
                        bitPos++;
                    }

                int[] A = new int[8];
                for (int i = 0; i < 8; i++)
                    for (int j = 0; j < 8; j++)
                        if (((Integer.bitCount(L[i] & U[j])) & 1) == 1)
                            A[i] |= (1 << (7 - j));
                int[] box    = new int[256];
                int[] invBox = new int[256];
                for (int x = 0; x < 256; x++) {
                    int y = gf2MatVecMul(A, GF_INV[x]) ^ c;
                    box[x]    = y;
                    invBox[y] = x;
                }

                ks.sbox[r][w]    = box;
                ks.sboxInv[r][w] = invBox;
            }
        }

        return ks;
    }

    static void shiftWords(long[] st) {
        for (int i = 0; i < WORDS; i++)
            st[i] = Long.rotateLeft(st[i], i * 8);
    }

    static void unshiftWords(long[] st) {
        for (int i = 0; i < WORDS; i++)
            st[i] = Long.rotateRight(st[i], i * 8);
    }

    static byte[] encryptBlock(byte[] in, KeySchedule ks, byte[] iv) {
        long[] st = bytesToState(in);
        long[] v  = bytesToState(iv);
        for (int i = 0; i < WORDS; i++) st[i] ^= v[i];
        for (int i = 0; i < WORDS; i++) st[i] ^= ks.roundKeys[0][i];
        for (int r = 0; r < ROUNDS; r++) {
            for (int i = 0; i < WORDS; i++) {
                long x = st[i], y = 0;
                for (int b = 0; b < 8; b++) {
                    int vb = (int)((x >>> (56 - b * 8)) & 0xFF);
                    y = (y << 8) | ks.sbox[r][i][vb];
                }
                st[i] = y;
            }            shiftWords(st);
            if (r < ROUNDS - 1) mixWords(st, false);
            for (int i = 0; i < WORDS; i++) st[i] ^= ks.roundKeys[r][i];
        }

        return stateToBytes(st);
    }

    static byte[] decryptBlock(byte[] in, KeySchedule ks, byte[] iv) {
        long[] st = bytesToState(in);

        for (int r = ROUNDS - 1; r >= 0; r--) {
            for (int i = 0; i < WORDS; i++) st[i] ^= ks.roundKeys[r][i];
            if (r < ROUNDS - 1) mixWords(st, true);
            unshiftWords(st);

            for (int i = 0; i < WORDS; i++) {
                long y = st[i], x = 0;
                for (int b = 0; b < 8; b++) {
                    int vb = (int)((y >>> (56 - b * 8)) & 0xFF);
                    x = (x << 8) | ks.sboxInv[r][i][vb];
                }
                st[i] = x;
            }
        }

        for (int i = 0; i < WORDS; i++) st[i] ^= ks.roundKeys[0][i];
        long[] v = bytesToState(iv);
        for (int i = 0; i < WORDS; i++) st[i] ^= v[i];

        return stateToBytes(st);
    }

    static byte[] pad(byte[] p) {
        int padLen = BLOCK_SIZE - (p.length % BLOCK_SIZE);
        byte[] data = Arrays.copyOf(p, p.length + padLen);
        Arrays.fill(data, p.length, data.length, (byte) padLen);
        return data;
    }

    static byte[] unpad(byte[] data) {
        if (data.length == 0 || data.length % BLOCK_SIZE != 0)
            throw new IllegalArgumentException("Bad ciphertext length");
        int pad = data[data.length - 1] & 0xFF;
        if (pad < 1 || pad > BLOCK_SIZE)
            throw new IllegalArgumentException("Invalid padding value: " + pad);
        for (int i = data.length - pad; i < data.length; i++)
            if ((data[i] & 0xFF) != pad)
                throw new IllegalArgumentException("Padding mismatch");
        return Arrays.copyOf(data, data.length - pad);
    }


    static String encrypt(String msg, byte[] k, byte[] s) {
        return encrypt(msg, build(k, s));
    }

    static String encrypt(String msg, KeySchedule ks) {
        byte[] data = pad(msg.getBytes(StandardCharsets.UTF_8));

        SecureRandom rng = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        rng.nextBytes(iv);

        byte[] ct   = new byte[data.length];
        byte[] prev = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int i = 0; i < data.length; i += BLOCK_SIZE) {
            byte[] blk = Arrays.copyOfRange(data, i, i + BLOCK_SIZE);
            byte[] enc = encryptBlock(blk, ks, prev);
            System.arraycopy(enc, 0, ct, i, BLOCK_SIZE);
            prev = enc;
        }
        byte[] payload = new byte[IV_SIZE + ct.length];
        System.arraycopy(iv, 0, payload, 0,      IV_SIZE);
        System.arraycopy(ct, 0, payload, IV_SIZE, ct.length);
        byte[] mac = hmacSha256(ks.macKey, payload);

        byte[] full = new byte[payload.length + MAC_SIZE];
        System.arraycopy(payload, 0, full, 0,              payload.length);
        System.arraycopy(mac,     0, full, payload.length, MAC_SIZE);

        return new String(full, StandardCharsets.ISO_8859_1);
    }

    static String decrypt(String c, byte[] k, byte[] s) {
        return decrypt(c, build(k, s));
    }

    static String decrypt(String c, KeySchedule ks) {
        byte[] raw = c.getBytes(StandardCharsets.ISO_8859_1);
        if (raw.length < IV_SIZE + BLOCK_SIZE + MAC_SIZE)
            throw new IllegalArgumentException("Ciphertext too short");
        byte[] payload  = Arrays.copyOf(raw, raw.length - MAC_SIZE);
        byte[] macGiven = Arrays.copyOfRange(raw, raw.length - MAC_SIZE, raw.length);
        byte[] macCalc = hmacSha256(ks.macKey, payload);
        if (!MessageDigest.isEqual(macCalc, macGiven))
            throw new SecurityException("MAC verification failed — ciphertext tampered");

        byte[] iv   = Arrays.copyOf(payload, IV_SIZE);
        byte[] body = Arrays.copyOfRange(payload, IV_SIZE, payload.length);

        byte[] out  = new byte[body.length];
        byte[] prev = Arrays.copyOf(iv, BLOCK_SIZE);

        for (int i = 0; i < body.length; i += BLOCK_SIZE) {
            byte[] blk = Arrays.copyOfRange(body, i, i + BLOCK_SIZE);
            byte[] dec = decryptBlock(blk, ks, prev);
            System.arraycopy(dec, 0, out, i, BLOCK_SIZE);
            prev = blk;
        }

        return new String(unpad(out), StandardCharsets.UTF_8);
    }
