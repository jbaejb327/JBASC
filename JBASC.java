import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.function.Function;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class JBASC {

    static final int WORDS      = 8;
    static final int ROUNDS     = 10;
    static final int BLOCK_SIZE = 64;
    static final int IV_SIZE    = BLOCK_SIZE;
    static final int MAC_SIZE   = 32;
    static final int[] ROT = {3, 11, 17, 29, 37, 43, 53, 61};

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

    static final int[][] MDS8 = {
        {7, 67, 150, 174, 198, 136, 98, 8},
        {76, 138, 43, 233, 32, 152, 8, 127},
        {96, 213, 67, 172, 11, 174, 51, 185},
        {181, 19, 224, 141, 168, 58, 29, 132},
        {134, 86, 57, 197, 69, 79, 14, 93},
        {165, 147, 160, 68, 26, 105, 64, 188},
        {163, 125, 208, 6, 217, 104, 5, 73},
        {59, 176, 117, 146, 234, 96, 60, 106},
    };
    
    static final int[][] MDS8_INV = gf28MatInverse(MDS8);
    
    static int[] gf28MatVecMul(int[][] M, int[] v) {
        int[] out = new int[8];
        for (int i = 0; i < 8; i++) {
            int acc = 0;
            for (int j = 0; j < 8; j++) acc ^= GF_MUL[M[i][j]][v[j]];
            out[i] = acc;
        }
        return out;
    }
    static void gf28MatVecMulInPlace(int[][] M, int[] col, int[] out) {
    for (int i = 0; i < 8; i++) {
        int sum = 0;
        int[] row = M[i]; 
        for (int j = 0; j < 8; j++) {
            sum ^= gfMul(row[j], col[j]); 
        }
        out[i] = sum;
    }
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
    static final int[][][] MDS_FWD_LUT = buildMdsLut(MDS8);
static final int[][][] MDS_INV_LUT = buildMdsLut(MDS8_INV);

static int[][][] buildMdsLut(int[][] m) {
    int[][][] lut = new int[8][8][256];
    for (int row = 0; row < 8; row++) {
        for (int col = 0; col < 8; col++) {
            int coeff = m[row][col];
            for (int b = 0; b < 256; b++) {
                lut[row][col][b] = GF_MUL[coeff][b];
            }
        }
    }

    return lut;
}
    static void crossMix(long[] st) {
    long[] tmp = st.clone();
    for (int i = 0; i < WORDS; i++) {
        long a = tmp[(i + 1) & 7];
        long b = tmp[(i + 3) & 7];
        st[i] ^= Long.rotateLeft(a, 17);
        st[i] += Long.rotateLeft(b, 41);
    }
}

static void mixWords(long[] st, boolean inverse) {

    final int[][][] LUT =
        inverse ? MDS_INV_LUT : MDS_FWD_LUT;
    final int[] col   = new int[8];
    final int[] mixed = new int[8];
    for (int lane = 0; lane < 8; lane++) {
        final int shift = 56 - (lane << 3);
        for (int i = 0; i < 8; i++) {
            col[i] = (int)((st[i] >>> shift) & 0xFF);
        }

        for (int row = 0; row < 8; row++) {
            mixed[row] =
                LUT[row][0][col[0]]
                ^ LUT[row][1][col[1]]
                ^ LUT[row][2][col[2]]
                ^ LUT[row][3][col[3]]
                ^ LUT[row][4][col[4]]
                ^ LUT[row][5][col[5]]
                ^ LUT[row][6][col[6]]
                ^ LUT[row][7][col[7]];
        }

        final long clearMask = ~(0xFFL << shift);
        for (int i = 0; i < 8; i++) {
            st[i] =
                (st[i] & clearMask)
                | (((long)mixed[i] & 0xFFL) << shift);
        }
    }
}

    static class KeySchedule {
        long[][]   roundKeys = new long[ROUNDS][WORDS];
        int[][][]  sbox      = new int[ROUNDS][WORDS][256];
    }

static KeySchedule build(byte[] k, byte[] s) {
    KeySchedule ks = new KeySchedule();
    byte[] cipherKey =
        sha256(k, s, "CIPHER".getBytes(StandardCharsets.UTF_8));
    byte[] rk =
        expand(cipherKey, s, "RK".getBytes(StandardCharsets.UTF_8),
               ROUNDS * WORDS * 8);
    for (int r = 0; r < ROUNDS; r++) {
        for (int i = 0; i < WORDS; i++) {
            ks.roundKeys[r][i] =
                bytesToLong8(rk, (r * WORDS + i) * 8);
        }
    }

    byte[] sboxSeed =
        expand(cipherKey, s, "SBOX".getBytes(StandardCharsets.UTF_8),
               ROUNDS * WORDS * 64);

    int seedOff = 0;
    for (int r = 0; r < ROUNDS; r++) {
        for (int w = 0; w < WORDS; w++) {
            int[] A;
            while (true) {
                A = new int[8];
                for (int row = 0; row < 8; row++) {
                    int bits = 0;
                    for (int col = 0; col < 8; col++) {
                        int idx =
                            (seedOff + row * 8 + col) % sboxSeed.length;
                        int bit =
                            (sboxSeed[idx] >>> (col & 7)) & 1;
                        bits |= (bit << (7 - col));
                    }
                    A[row] = bits;
                }
                seedOff += 64;
                if (isInvertibleGF2(A))
                    break;
            }
            int c =
                sboxSeed[(seedOff++) % sboxSeed.length] & 0xFF;
            int[] box = new int[256];
            for (int x = 0; x < 256; x++) {
                int inv = GF_INV[x];
                int y = gf2MatVecMul(A, inv) ^ c;
                box[x] = y & 0xFF;
            }
            ks.sbox[r][w] = box;
        }
    }
    return ks;
}

static boolean isInvertibleGF2(int[] M) {
    int[] mat = M.clone();
    int rank = 0;
    for (int col = 0; col < 8; col++) {
        int pivot = -1;
        for (int row = rank; row < 8; row++) {
            if (((mat[row] >>> (7 - col)) & 1) == 1) {
                pivot = row;
                break;
            }
        }

        if (pivot == -1)
            continue;
        int tmp = mat[rank];
        mat[rank] = mat[pivot];
        mat[pivot] = tmp;
        for (int row = 0; row < 8; row++) {
            if (row != rank &&
                (((mat[row] >>> (7 - col)) & 1) == 1)) {
                mat[row] ^= mat[rank];
            }
        }

        rank++;
    }
    return rank == 8;
}

static void shiftWords(long[] st) {
    for (int i = 0; i < WORDS; i++) {
        st[i] = Long.rotateLeft(st[i], ROT[i]);
    }
}

static byte[] encryptBlock(byte[] in, KeySchedule ks, byte[] iv) {
    long[] st = bytesToState(in);
    long[] v  = bytesToState(iv);
    for (int i = 0; i < WORDS; i++) {
        st[i] ^= v[i];
    }
    for (int r = 0; r < ROUNDS; r++) {
        for (int i = 0; i < WORDS; i++) {
            st[i] ^= ks.roundKeys[r][i];
        }
        for (int i = 0; i < WORDS; i++) {
            long x = st[i];
            long y = 0;
            for (int b = 0; b < 8; b++) {
                int vb = (int)((x >>> (56 - b * 8)) & 0xFF);
                y = (y << 8) | ks.sbox[r][i][vb];
            }
            st[i] = y;
        }
        crossMix(st);
        shiftWords(st);
        mixWords(st, false);
        for (int i = 0; i < WORDS; i++) {
        }
    }

    return stateToBytes(st);
}
