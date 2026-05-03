import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class JBASCFile {

    static final byte[] MAGIC   = {'J','B','A','S'};
    static final byte   VERSION = 0x02;

    static void encryptFile(Path inPath, byte[] k, byte[] s) throws Exception {
        String originalName = inPath.getFileName().toString();
        byte[] nameBytes    = originalName.getBytes(StandardCharsets.UTF_8);
        if (nameBytes.length > 255)
            throw new IllegalArgumentException("Filename too long (max 255 UTF-8 bytes)");

        Path outPath = inPath.resolveSibling(stripExtension(originalName) + ".jbas");

        JBASC.KeySchedule ks = JBASC.build(k, s);

        SecureRandom rng = new SecureRandom();
        byte[] iv = new byte[JBASC.BLOCK_SIZE];
        rng.nextBytes(iv);

        long fileSize = Files.size(inPath);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(ks.macKey, "HmacSHA256"));

        Path tempPath = Files.createTempFile("jbasc_", ".tmp");
        try {
            try (InputStream  raw  = new BufferedInputStream(Files.newInputStream(inPath), 65536);
                 OutputStream temp = new BufferedOutputStream(Files.newOutputStream(tempPath), 65536);
                 GZIPOutputStream gzip = new GZIPOutputStream(temp, 65536) {{
                     def.setLevel(1);
                 }}) {
                raw.transferTo(gzip);
            }

            long compressedSize = Files.size(tempPath);


            try (InputStream  in  = new BufferedInputStream(Files.newInputStream(tempPath), 65536);
                 OutputStream out = new BufferedOutputStream(Files.newOutputStream(outPath), 65536)) {


                writeAndMac(out, mac, MAGIC);
                writeAndMac(out, mac, new byte[]{VERSION});
                writeAndMac(out, mac, new byte[]{(byte) nameBytes.length});
                writeAndMac(out, mac, nameBytes);
                writeAndMac(out, mac, iv);
                writeAndMac(out, mac, longToBytes(compressedSize));


                byte[] prev    = Arrays.copyOf(iv, JBASC.BLOCK_SIZE);
                byte[] block   = new byte[JBASC.BLOCK_SIZE];
                long   written = 0;

                while (written < compressedSize) {
                    long remaining = compressedSize - written;
                    int  want      = (int) Math.min(JBASC.BLOCK_SIZE, remaining);
                    int  got       = readFully(in, block, 0, want);
                    if (got < want) throw new IOException("Compressed data shorter than expected");

                    if (want < JBASC.BLOCK_SIZE) {
                        int padLen = JBASC.BLOCK_SIZE - want;
                        Arrays.fill(block, want, JBASC.BLOCK_SIZE, (byte) padLen);
                    }

                    byte[] enc = JBASC.encryptBlock(block, ks, prev);
                    writeAndMac(out, mac, enc);
                    prev    = enc;
                    written += want;
                }

                if (compressedSize % JBASC.BLOCK_SIZE == 0) {
                    Arrays.fill(block, (byte) JBASC.BLOCK_SIZE);
                    byte[] enc = JBASC.encryptBlock(block, ks, prev);
                    writeAndMac(out, mac, enc);
                }

                out.write(mac.doFinal());
                out.flush();
            }
        } finally {
            Files.deleteIfExists(tempPath);
        }

        long encSize = Files.size(outPath);
        System.out.println("Encrypted: " + outPath.getFileName());
        System.out.printf("  original size   : %,d bytes%n", fileSize);
        System.out.printf("  encrypted size  : %,d bytes%n", encSize);
        System.out.printf("  compression     : %.1f%%%n",
                fileSize > 0 ? (1.0 - (double) encSize / fileSize) * 100 : 0.0);
    }


    static void decryptFile(Path inPath, byte[] k, byte[] s) throws Exception {
        if (!inPath.toString().endsWith(".jbas"))
            throw new IllegalArgumentException("Not a .jbas file: " + inPath);

        byte[] raw = Files.readAllBytes(inPath);

        if (raw.length < MAGIC.length + 1 + 1 + JBASC.BLOCK_SIZE + 8 + JBASC.BLOCK_SIZE + JBASC.MAC_SIZE)
            throw new IllegalArgumentException("File too short to be a valid .jbas file");

        JBASC.KeySchedule ks = JBASC.build(k, s);
        byte[] payload  = Arrays.copyOf(raw, raw.length - JBASC.MAC_SIZE);
        byte[] macGiven = Arrays.copyOfRange(raw, raw.length - JBASC.MAC_SIZE, raw.length);
        byte[] macCalc  = hmac(ks.macKey, payload);
        if (!MessageDigest.isEqual(macCalc, macGiven))
            throw new SecurityException("MAC verification failed — file tampered or wrong key/salt");

        int pos = 0;
        for (byte b : MAGIC)
            if (raw[pos++] != b)
                throw new IllegalArgumentException("Invalid magic — not a .jbas file");

        byte version = raw[pos++];
        if (version != VERSION)
            throw new IllegalArgumentException("Unsupported .jbas version: 0x"
                    + String.format("%02X", version) + " (expected 0x02)");

        int    nameLen  = raw[pos++] & 0xFF;
        String origName = new String(raw, pos, nameLen, StandardCharsets.UTF_8);
        pos += nameLen;

        byte[] iv = Arrays.copyOfRange(raw, pos, pos + JBASC.BLOCK_SIZE);
        pos += JBASC.BLOCK_SIZE;

        long compressedSize = bytesToLong(raw, pos);
        pos += 8;

        Path tempPath = Files.createTempFile("jbasc_", ".tmp");
        try {
            try (OutputStream temp = new BufferedOutputStream(Files.newOutputStream(tempPath), 65536)) {
                byte[] prev    = Arrays.copyOf(iv, JBASC.BLOCK_SIZE);
                long   written = 0;
                int    ctEnd   = raw.length - JBASC.MAC_SIZE;

                while (pos < ctEnd) {
                    byte[] block = Arrays.copyOfRange(raw, pos, pos + JBASC.BLOCK_SIZE);
                    pos += JBASC.BLOCK_SIZE;
                    byte[] dec  = JBASC.decryptBlock(block, ks, prev);
                    prev = block;

                    boolean isLast = (pos >= ctEnd);
                    if (isLast) {
                        int pad = dec[JBASC.BLOCK_SIZE - 1] & 0xFF;
                        if (pad < 1 || pad > JBASC.BLOCK_SIZE)
                            throw new IllegalArgumentException("Invalid padding");
                        if (written < compressedSize) {
                            int keep = (int) Math.min(JBASC.BLOCK_SIZE - pad, compressedSize - written);
                            temp.write(dec, 0, keep);
                            written += keep;
                        }
                    } else {
                        long toWrite = Math.min(JBASC.BLOCK_SIZE, compressedSize - written);
                        temp.write(dec, 0, (int) toWrite);
                        written += toWrite;
                    }
                }
                temp.flush();
            }

            Path outPath = inPath.resolveSibling(origName);
            try (InputStream  gzip = new GZIPInputStream(
                                         new BufferedInputStream(Files.newInputStream(tempPath), 65536));
                 OutputStream out  = new BufferedOutputStream(Files.newOutputStream(outPath), 65536)) {
                gzip.transferTo(out);
            }

            System.out.println("Decrypted: " + origName);
            System.out.printf("  restored size: %,d bytes%n", Files.size(outPath));
        } finally {
            Files.deleteIfExists(tempPath);
        }
    }


    static void writeAndMac(OutputStream out, Mac mac, byte[] data) throws IOException {
        out.write(data);
        mac.update(data);
    }

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) { throw new RuntimeException(e); }
    }

    static byte[] longToBytes(long v) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) { b[i] = (byte)(v & 0xFF); v >>= 8; }
        return b;
    }

    static long bytesToLong(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) v = (v << 8) | (b[off + i] & 0xFFL);
        return v;
    }

    static int readFully(InputStream in, byte[] buf, int off, int len) throws IOException {
        int total = 0;
        while (total < len) {
            int n = in.read(buf, off + total, len - total);
            if (n == -1) break;
            total += n;
        }
        return total;
    }

    static String stripExtension(String name) {
        int dot = name.lastIndexOf('.');
        return dot > 0 ? name.substring(0, dot) : name;
    }


        public static void main(String[] args) {
    if (args.length != 4) {
        System.out.println("Usage:");
        System.out.println("  Encrypt: java JBASCFile encrypt <file> <key> <salt>");
        System.out.println("  Decrypt: java JBASCFile decrypt <file.jbas> <key> <salt>");
        System.exit(1);
    }

    String mode = args[0].toLowerCase();
    Path file   = Path.of(args[1]);
    byte[] k    = args[2].getBytes(StandardCharsets.UTF_8);
    byte[] s    = args[3].getBytes(StandardCharsets.UTF_8);

        if (!Files.exists(file)) {
            System.err.println("File not found: " + file);
            System.exit(1);
        }

        try {
            long start = System.currentTimeMillis();
            switch (mode) {
                case "encrypt" -> encryptFile(file, k, s);
                case "decrypt" -> decryptFile(file, k, s);
                default -> {
                    System.err.println("Unknown mode: " + mode + " (use encrypt or decrypt)");
                    System.exit(1);
                }
            }
            long elapsed = System.currentTimeMillis() - start;
            System.out.printf("  time: %dms%n", elapsed);
        } catch (SecurityException e) {
            System.err.println("SECURITY ERROR: " + e.getMessage());
            System.exit(2);
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(1);
        }
    }
}
