import java.io.*;
import java.nio.file.*;
import java.util.*;

public class CryptoConfig {
    private String cipher;
    private Integer keySize;
    private String hmacAlgorithm;
    private Integer macKeySize;
    private Integer ivLength;
    private Integer nonceLength;
    private Integer tagLength;

    private boolean needsIV;
    private boolean needsNonce;
    private boolean needsHMAC;
    private boolean isAEAD;


    public static CryptoConfig load(String path) throws IOException {
        CryptoConfig config = new CryptoConfig();

        File configFile = new File(path);
        if (!configFile.exists()) {
            throw new FileNotFoundException("Crypto config file not found: " + path);
        }

        List<String> lines = Files.readAllLines(Paths.get(path));

        for (String line : lines) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            String upperLine = line.toUpperCase();

            if (upperLine.startsWith("KEYSIZE:")) {
                config.keySize = parseIntValue(line);
            } else if (upperLine.startsWith("MACKEYSIZE:") || upperLine.startsWith("HMACKEYSIZE:")) {
                config.macKeySize = parseIntValue(line);
            } else if (upperLine.startsWith("IV_LENGTH:")) {
                config.ivLength = parseIntValue(line);
            } else if (upperLine.startsWith("NONCE_LENGTH:")) {
                config.nonceLength = parseIntValue(line);
            } else if (upperLine.startsWith("TAG_LENGTH:")) {
                config.tagLength = parseIntValue(line);
            } else if (upperLine.startsWith("HMAC-")) {
                config.hmacAlgorithm = "Hmac" + line.substring(5);
            } else if (!line.contains(":")) {
                config.cipher = line;
            }
        }

        if (config.cipher == null) {
            throw new IOException("No cipher specified in configuration file");
        }

        config.computeAndValidate();
        return config;
    }

    private static int parseIntValue(String line) {
        String[] parts = line.split(":", 2);
        if (parts.length < 2) {
            throw new IllegalArgumentException("Invalid config line: " + line);
        }
        //ignore "bits"/"bytes"
        String value = parts[1].trim().split("\\s+")[0];
        return Integer.parseInt(value);
    }

    private void computeAndValidate() {
        String upperCipher = cipher.toUpperCase();

        isAEAD = upperCipher.contains("GCM") ||
                upperCipher.contains("CCM") ||
                upperCipher.contains("CHACHA20-POLY1305");

        //determine whats needed based on cipher
        //for AEAD ciphers
        if (isAEAD) {
            needsNonce = true;
            needsIV = false;
            needsHMAC = false;

            //set defaults if not specified
            if (nonceLength == null) {
                nonceLength = 12;
            }
            if (tagLength == null) {
                tagLength = 128;
            }
        //for ECB
        } else if (cipher.contains("ECB")) {
            needsIV = false;
            needsNonce = false;
            needsHMAC = true;
            if(hmacAlgorithm == null) {
                hmacAlgorithm = "HmacSHA256";
            }
        //Non-AEAD
        } else {
            needsIV = true;
            needsNonce = false;
            needsHMAC = true;

            if (ivLength == null) {
                ivLength = 16;
            }
            if(hmacAlgorithm == null) {
                hmacAlgorithm = "HmacSHA256";
            }
        }

        if (keySize == null) {
            keySize = 256;
        }

        if (needsHMAC && macKeySize == null && hmacAlgorithm == null) {
                String upperHmac = hmacAlgorithm.toUpperCase();
                System.out.println(upperHmac);
                if (upperHmac.contains("SHA256")) {
                    macKeySize = 256;
                } else if (upperHmac.contains("SHA512")) {
                    macKeySize = 512;
                } else if (upperHmac.contains("SHA1")) {
                    macKeySize = 160;
                } else {
                    macKeySize = 256; //default
                }
        }

        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new IllegalArgumentException("Invalid key size: " + keySize + ". Must be 128, 192, or 256.");
        }
    }

    public String getCipher() {
        return cipher;
    }

    public int getKeySize() {
        return keySize;
    }

    public String getHmacAlgorithm() {
        return hmacAlgorithm;
    }

    public Integer getMacKeySize() {
        return macKeySize;
    }

    public Integer getIVLength() {
        return ivLength;
    }

    public Integer getNonceLength() {
        return nonceLength;
    }

    public Integer getTagLength() {
        return tagLength;
    }

    public boolean needsIV() {
        return needsIV;
    }

    public boolean needsNonce() {
        return needsNonce;
    }

    public boolean needsHMAC() {
        return needsHMAC;
    }

    public boolean isAEAD() {
        return isAEAD;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Crypto Configuration ===\n");
        sb.append("Cipher: ").append(cipher).append("\n");
        sb.append("Key Size: ").append(keySize).append(" bits\n");
        sb.append("AEAD Mode: ").append(isAEAD ? "Yes" : "No").append("\n");

        if (needsNonce && nonceLength != null) {
            sb.append("Nonce Length: ").append(nonceLength).append(" bytes\n");
        }
        if (needsIV && ivLength != null) {
            sb.append("IV Length: ").append(ivLength).append(" bytes\n");
        }
        if (isAEAD && tagLength != null) {
            sb.append("Tag Length: ").append(tagLength).append(" bits\n");
        }
        if (needsHMAC && hmacAlgorithm != null) {
            sb.append("HMAC Algorithm: ").append(hmacAlgorithm).append("\n");
            if (macKeySize != null) {
                sb.append("MAC Key Size: ").append(macKeySize).append(" bits\n");
            }
        }

        sb.append("\nRequired Components:\n");
        sb.append("  - IV: ").append(needsIV ? "Yes" : "No").append("\n");
        sb.append("  - Nonce: ").append(needsNonce ? "Yes" : "No").append("\n");
        sb.append("  - HMAC: ").append(needsHMAC ? "Yes" : "No").append("\n");

        return sb.toString();
    }
}