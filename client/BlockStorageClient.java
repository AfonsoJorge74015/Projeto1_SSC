
import java.io.*;
import java.net.*;
import java.util.*;

public class BlockStorageClient {
    private static final int PORT = 5000;
    private static final int BLOCK_SIZE = 4096;
    private static final String INDEX_FILE = "client_index.ser";

    private static Map<String, List<String>> fileIndex = new HashMap<>();

    public static void main(String[] args) throws IOException, ClassNotFoundException {
        loadIndex();

        Socket socket = new Socket("localhost", PORT);
        try (
            DataInputStream in = new DataInputStream(socket.getInputStream());
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            Scanner scanner = new Scanner(System.in);
        ) {
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

    private static void putFile(File file, List<String> keywords, DataOutputStream out, DataInputStream in) throws IOException {
        List<String> blocks = new ArrayList<>();
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead;
            int blockNum = 0;
            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] blockData = Arrays.copyOf(buffer, bytesRead);
                String blockId = file.getName() + "_block_" + blockNum++;

                out.writeUTF("STORE_BLOCK");
                out.writeUTF(blockId);
                out.writeInt(blockData.length);
                out.write(blockData);
		System.out.print("."); // Just for debug

                // Send keywords for first block only
                if (blockNum == 1) {
                    out.writeInt(keywords.size());
                    for (String kw : keywords) out.writeUTF(kw);
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

    private static void getFile(String filename, DataOutputStream out, DataInputStream in) throws IOException {
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
                byte[] data = new byte[length];
                in.readFully(data);
		System.out.print("."); // Just for debug 
                fos.write(data);
            }
        }
	System.out.println();	
        System.out.println("File reconstructed: retrieved_" + filename);
    }

    private static void searchFiles(String keyword, DataOutputStream out, DataInputStream in) throws IOException {
        out.writeUTF("SEARCH");
        out.writeUTF(keyword.toLowerCase());
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
}
