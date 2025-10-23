
import java.io.*;
import java.net.*;
import java.nio.channels.Channel;
import java.util.*;
import java.security.Key;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import javax.sql.rowset.spi.SyncResolver;

public class BlockStorageClient {
    private static final int PORT = 5000;
    private static final int BLOCK_SIZE = 4096;
    private static final int SALT_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int PROTECTION_KEY_SIZE = 256;

    private static CryptoConfig cryptoConfig;
    private static SecretKey encryptionKey;
    private static SecretKey macKey;

    private static final String INDEX_FILE = "client_index.ser";
    private static final String KEY_FILE = "keys.txt";
    private static final String MAC_KEY_FILE = "mac_key.txt";
    private static final String CONFIG_FILE = "cryptoconfig.txt";

    private static Map<String, List<String>> fileIndex = new HashMap<>();

    public static void main(String[] args) throws Exception {
        try {
            cryptoConfig = CryptoConfig.load(CONFIG_FILE);
            System.out.println(cryptoConfig);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            return;
        }

        loadIndex();

        Socket socket = new Socket("localhost", PORT);

        try (
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            Scanner scanner = new Scanner(System.in)
        ) {
            System.out.print("Enter password for key: ");
            char[] password = scanner.nextLine().toCharArray(); 
            encryptionKey = loadOrGenKey( KEY_FILE, password);
            macKey = loadOrGenKey( MAC_KEY_FILE, password);

            while (true) {
                System.out.print("Command (PUT/GET/LIST/SEARCH/EXIT): ");
                String cmd = scanner.nextLine().toUpperCase();

                switch (cmd) {
                    case "PUT":
                        System.out.print("Enter local file path: ");
                        String path = scanner.nextLine();
                        File file = new File(path);
                        if (!file.exists()) {
                            System.out.println("File does not exist.");
                            continue;
                        }
                        System.out.print("Enter keywords (comma-separated): ");
                        String kwLine = scanner.nextLine();
                        List<String> keywords = new ArrayList<>();
                        while(kwLine.trim().isEmpty()){
                            System.out.print("\nNo keywords. Please input atleast one valid keyword\n");
                            System.out.print("Enter keywords (comma-separated): ");
                            kwLine = scanner.nextLine();
                        }
                        for (String kw : kwLine.split(",")){
                            keywords.add(kw.trim().toLowerCase());
                        }
                        putFile(file, keywords, out, in);
                        saveIndex();
                        break;

                    case "GET":
                        System.out.print("Enter filename to retrieve: ");
                        String filename = scanner.nextLine();
                        getFile(filename, out, in);
                        break;

                    case "LIST":
                        if(fileIndex.isEmpty()) {
                            System.out.println("No stored files.");
                            break;
                        }
                        System.out.println("Stored files:");
                        for (String f : fileIndex.keySet()) System.out.println(" - " + f);
                        break;

                    case "SEARCH":
                        System.out.print("Enter keyword to search: ");
                        String keyword = scanner.nextLine();
                        searchFiles(keyword, out, in);
                        break;

                    case "EXIT":
                        out.writeUTF("EXIT");
                        out.flush();
                        saveIndex();
                        return;

                    default:
                        System.out.println("Unknown command.");
                        break;
                }
            }
        } finally {
            socket.close();
        }
    }

    private static void putFile(File file, List<String> keywords, DataOutputStream out, DataInputStream in) throws IOException, Exception {
        List<String> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead;
            int blockNum = 0;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] rawData = Arrays.copyOf(buffer, bytesRead);
                String blockId = file.getName() + "_block_" + blockNum++;

                byte[] blockData = encryptBlock(rawData);

                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] blockIdHash = digest.digest(blockId.getBytes(StandardCharsets.UTF_8));
                String blockIdHashStr = Base64.getEncoder().encodeToString(blockIdHash);

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(blockIdHashStr);
                out.writeInt(blockData.length);
                out.write(blockData);
		        System.out.print("."); // Just for debug

                // Send keywords for first block only
                if (blockNum == 1) {
                    out.writeInt(keywords.size());
                    for (String kw : keywords){
                        Mac mac = Mac.getInstance("HmacSHA256");
                        mac.init(macKey);
                        byte[] token = mac.doFinal(kw.getBytes(StandardCharsets.UTF_8));
                        out.writeUTF(Base64.getEncoder().encodeToString(token));
                    }
                } else {
                    out.writeInt(0); // no keywords for other blocks
                }

                out.flush();
                String response = in.readUTF();
                if (!response.equals("OK")) {
                    System.out.println("Error storing block: " + blockId);
                    return;
                }
                blocks.add(blockId);
            }
        }
        
        fileIndex.put(file.getName(), blocks);
	    System.out.println();
	    System.out.println("File stored with " + blocks.size() + " blocks.");
    }

    private static void getFile(String filename, DataOutputStream out, DataInputStream in) throws Exception {
        List<String> blocks = fileIndex.get(filename);
        if (blocks == null) {
	    System.out.println();	    
            System.out.println("File not found in local index.");
            return;
        }
        try (FileOutputStream fos = new FileOutputStream("retrieved_" + filename)) {
            for (String blockId : blocks) {
                out.writeUTF("GET_BLOCK");
                out.writeUTF(blockId);
                out.flush();
                int length = in.readInt();
                if (length == -1) {
                    System.out.println("Block not found: " + blockId);
                    return;
                }
                byte[] encryptedData = new byte[length];
                in.readFully(encryptedData);           // read from server
                byte[] data = decryptBlock(encryptedData); // then decrypt

		        System.out.print("."); // Just for debug
                fos.write(data);
            }
        }
	System.out.println();	
        System.out.println("File reconstructed: retrieved_" + filename);
    }

    private static void searchFiles(String keyword, DataOutputStream out, DataInputStream in) throws IOException, Exception {
        out.writeUTF("SEARCH");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(macKey);
        byte[] token = mac.doFinal(keyword.getBytes(StandardCharsets.UTF_8));
        out.writeUTF(Base64.getEncoder().encodeToString(token));
        out.flush();
        int count = in.readInt();
        if(count > 0){
            System.out.println("\nSearch results:");
            for (int i = 0; i < count; i++) {
                System.out.println(" - " + in.readUTF());
            }
            System.out.println();
        } else {
            System.out.println("\nNo files found\n");
        }
    }

    private static void saveIndex() {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(INDEX_FILE))) {
            oos.writeObject(fileIndex);
        } catch (IOException e) {
            System.err.println("Failed to save index: " + e.getMessage());
        }
    }

    private static void loadIndex() {
        File f = new File(INDEX_FILE);
        if (!f.exists()) return;
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(f))) {
            fileIndex = (Map<String, List<String>>) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.err.println("Failed to load index: " + e.getMessage());
        }
    }

    //Encrypt/Decrypt
    private static byte[] encryptBlock(byte[] data) throws Exception {
        if (cryptoConfig.isAEAD()) {
            return encryptAEAD(data);
        } else {
            byte[] ciphertext = encryptNonAEAD(data);
            if (cryptoConfig.needsHMAC()) {
                return addHMAC(ciphertext);
            }
            return ciphertext;
        }
    }

    private static byte[] decryptBlock(byte[] encrypted) throws Exception {
        if (cryptoConfig.isAEAD()) {
            return decryptAEAD(encrypted);
        } else {
            if (cryptoConfig.needsHMAC()) {
                encrypted = verifyAndRemoveHMAC(encrypted);
            }
            return decryptNonAEAD(encrypted);
        }
    }

    //for AEAD
    private static byte[] encryptAEAD(byte[] data) throws Exception {
        int nonceLen = cryptoConfig.getNonceLength();
        byte[] nonce = new byte[nonceLen];
        new SecureRandom().nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(cryptoConfig.getCipher());

        if (cryptoConfig.getCipher().toUpperCase().contains("GCM")) {
            GCMParameterSpec spec = new GCMParameterSpec(cryptoConfig.getTagLength(), nonce);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);
        } else {
            IvParameterSpec spec = new IvParameterSpec(nonce);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, spec);
        }

        byte[] ciphertext = cipher.doFinal(data);

        byte[] result = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);
        return result;
    }

    private static byte[] decryptAEAD(byte[] encrypted) throws Exception {
        int nonceLen = cryptoConfig.getNonceLength();
        byte[] nonce = new byte[nonceLen];
        System.arraycopy(encrypted, 0, nonce, 0, nonceLen);

        byte[] ciphertext = new byte[encrypted.length - nonceLen];
        System.arraycopy(encrypted, nonceLen, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(cryptoConfig.getCipher());

        if (cryptoConfig.getCipher().toUpperCase().contains("GCM")) {
            GCMParameterSpec spec = new GCMParameterSpec(cryptoConfig.getTagLength(), nonce);
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, spec);
        } else {
            IvParameterSpec spec = new IvParameterSpec(nonce);
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, spec);
        }

        return cipher.doFinal(ciphertext);
    }

    //for non-AEAD
    private static byte[] encryptNonAEAD(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance(cryptoConfig.getCipher());

        if (cryptoConfig.needsIV()) {
            int ivLen = cryptoConfig.getIVLength();
            byte[] iv = new byte[ivLen];
            new SecureRandom().nextBytes(iv);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivSpec);
            byte[] ciphertext = cipher.doFinal(data);

            byte[] result = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
            return result;
        } else {
            //ECB mode (no IV)
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
            return cipher.doFinal(data);
        }
    }

    private static byte[] decryptNonAEAD(byte[] encrypted) throws Exception {
        Cipher cipher = Cipher.getInstance(cryptoConfig.getCipher());

        if (cryptoConfig.needsIV()) {
            int ivLen = cryptoConfig.getIVLength();
            byte[] iv = new byte[ivLen];
            System.arraycopy(encrypted, 0, iv, 0, ivLen);

            byte[] ciphertext = new byte[encrypted.length - ivLen];
            System.arraycopy(encrypted, ivLen, ciphertext, 0, ciphertext.length);

            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, ivSpec);
            return cipher.doFinal(ciphertext);
        } else {
            //ECB mode (no IV)
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
            return cipher.doFinal(encrypted);
        }
    }

    //HMAC
    private static byte[] addHMAC(byte[] data) throws Exception {
        Mac mac = Mac.getInstance(cryptoConfig.getHmacAlgorithm());
        mac.init(macKey);
        byte[] tag = mac.doFinal(data);

        byte[] result = new byte[data.length + tag.length];
        System.arraycopy(data, 0, result, 0, data.length);
        System.arraycopy(tag, 0, result, data.length, tag.length);
        return result;
    }

    private static byte[] verifyAndRemoveHMAC(byte[] dataWithMac) throws Exception {
        Mac mac = Mac.getInstance(cryptoConfig.getHmacAlgorithm());
        mac.init(macKey);

        int macLen = mac.getMacLength();
        byte[] data = new byte[dataWithMac.length - macLen];
        byte[] receivedMac = new byte[macLen];

        System.arraycopy(dataWithMac, 0, data, 0, data.length);
        System.arraycopy(dataWithMac, data.length, receivedMac, 0, macLen);

        byte[] computedMac = mac.doFinal(data);

        if (!MessageDigest.isEqual(computedMac, receivedMac)) {
            throw new SecurityException("HMAC verification failed! Data may have been tampered.");
        }

        return data;
    }

    //keys
    public static SecretKey loadOrGenKey(String filePath, char[] password) throws Exception {
        File keyFile = new File(filePath);
        if (keyFile.exists()) {
            return loadKey(filePath, password);
        } else {
            SecretKey newKey = genKey();
            saveKey(newKey, filePath, password);
            return newKey;
        }
    }

    private static SecretKey genKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(cryptoConfig.getKeySize());
        return keyGen.generateKey();
    }

    
    private static void saveKey(SecretKey key, String filePath, char[] password) throws Exception {
        // derive protection key
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        SecretKey protectionKey = deriveKeyFromPassword(password, salt);

        // encrypt AES key with protection key
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, protectionKey, spec);
        byte[] ciphertext = cipher.doFinal(key.getEncoded());

        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(filePath))) {
            writer.write(Base64.getEncoder().encodeToString(salt));
            writer.newLine();
            writer.write(Base64.getEncoder().encodeToString(nonce));
            writer.newLine();
            writer.write(Base64.getEncoder().encodeToString(ciphertext));
        }

    }

    private static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, PROTECTION_KEY_SIZE);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    private static SecretKey loadKey(String filePath, char[] password) throws Exception {
        List<String> lines = Files.readAllLines(Paths.get(filePath));
        byte[] salt = Base64.getDecoder().decode(lines.get(0));
        byte[] nonce = Base64.getDecoder().decode(lines.get(1));
        byte[] ciphertext = Base64.getDecoder().decode(lines.get(2));

        SecretKey protectionKey = deriveKeyFromPassword(password, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, nonce);
        cipher.init(Cipher.DECRYPT_MODE, protectionKey, spec);
        byte[] keyBytes = cipher.doFinal(ciphertext);

        return new SecretKeySpec(keyBytes, "AES");
    }
}
