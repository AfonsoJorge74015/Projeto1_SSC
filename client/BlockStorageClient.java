
import java.io.*;
import java.net.*;
import java.nio.channels.Channel;
import java.util.*;
import java.security.Key;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.KeySpec;
import javax.sql.rowset.spi.SyncResolver;

public class BlockStorageClient {
    private static final int PORT = 5000;
    private static final int BLOCK_SIZE = 4096;
    private static final int GCM_NONCE_LENGTH = 12; 
    private static final int AES_KEY_SIZE = 256; 
    private static final int GCM_TAG_LENGTH = 128;
    private static final int SALT_LENGTH = 16;
    private static final int PBKDF2_ITERATIONS = 65536;
    private static final int PROTECTION_KEY_SIZE = 256;
    private static SecretKey key;
    private static final String INDEX_FILE = "client_index.ser";
    private static final String KEY_FILE = "keys.txt";


    private static Map<String, List<String>> fileIndex = new HashMap<>();

    public static void main(String[] args) throws IOException, ClassNotFoundException, Exception {
        loadIndex();

        Socket socket = new Socket("localhost", PORT);

        try (
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            Scanner scanner = new Scanner(System.in);
            
        ) {
            System.out.print("Enter password for key: ");
            char[] password = scanner.nextLine().toCharArray(); 
            key = loadOrGenKey( KEY_FILE, password);

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
                        if (!kwLine.trim().isEmpty()) {
                            for (String kw : kwLine.split(",")) keywords.add(kw.trim().toLowerCase());
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

                byte[] blockData = encryptBlock(rawData, key);

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(blockId);
                out.writeInt(blockData.length);
                out.write(blockData);
		System.out.print("."); // Just for debug

                // Send keywords for first block only
                if (blockNum == 1) {
                    out.writeInt(keywords.size());
                    for (String kw : keywords){
                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                        byte[] token = digest.digest(kw.getBytes(StandardCharsets.UTF_8));
                        out.writeUTF(Base64.getEncoder().encodeToString(token));
                    }
		System.out.println("/nSent keywords./n"); // Just for debug    
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

    private static void getFile(String filename, DataOutputStream out, DataInputStream in) throws IOException, Exception {
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
                byte[] data = decryptBlock(encryptedData, key); // then decrypt

		System.out.print("."); // Just for debug 
                fos.write(data);
            }
        }
	System.out.println();	
        System.out.println("File reconstructed: retrieved_" + filename);
    }

    private static void searchFiles(String keyword, DataOutputStream out, DataInputStream in) throws IOException, Exception {
        out.writeUTF("SEARCH");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] token = digest.digest(keyword.toLowerCase().getBytes(StandardCharsets.UTF_8));
        out.writeUTF(Base64.getEncoder().encodeToString(token));
        out.flush();
        int count = in.readInt();
        System.out.println();	
        System.out.println("Search results:");
        for (int i = 0; i < count; i++) {
            System.out.println(" - " + in.readUTF());
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

    private static byte[] encryptBlock(byte[] data, SecretKey key) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);
       
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertext =cipher.doFinal(data);
        byte[] result = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, result, 0, nonce.length);
        System.arraycopy(ciphertext, 0, result, nonce.length, ciphertext.length);

        return result;

    }

    public static byte[] decryptBlock(byte[] encrypted, SecretKey key) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        System.arraycopy(encrypted, 0, nonce, 0, nonce.length);
        byte[] ciphertext = new byte[encrypted.length - nonce.length];
        System.arraycopy(encrypted, nonce.length, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);

        return cipher.doFinal(ciphertext);
    }

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
        keyGen.init(AES_KEY_SIZE);
        return keyGen.generateKey();
    }

    
    private static void saveKey(SecretKey key, String filePath, char[] password) throws Exception {
        // derive protection key
        byte[] salt = new byte[SALT_LENGTH];
        new SecureRandom().nextBytes(salt);
        SecretKey protectionKey = deriveKeyFromPassword(password, salt);

        // encrypt AES key with protection key
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
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
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, protectionKey, spec);
        byte[] keyBytes = cipher.doFinal(ciphertext);

        return new SecretKeySpec(keyBytes, "AES");
    }

}
