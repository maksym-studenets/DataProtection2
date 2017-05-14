import com.google.common.io.Resources;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.URL;

/**
 * Main method for S-DES decryption algorithm
 */
public class SDesDecryption {
    public static void main(String[] args) throws Exception {

        String keyString = readKey();
        //int key = readKey();
        System.out.print("Key: " + keyString);

        int key = Integer.parseInt(keyString, 2);
        System.out.println("");

        SDes sDes = new SDes(key);

        String[] split = readEncryptedStrings();
        if (split == null) throw new AssertionError();
        System.out.println("ENCRYPTED: ");
        for (String s : split) {
            System.out.print(s + " ");
        }

        int[] decrypted = new int[split.length];
        for (int i = 0; i < decrypted.length; i++) {
            int input = Integer.parseInt(split[i], 2);
            decrypted[i] = sDes.process(input, false);
        }

        System.out.println("");
        System.out.println("DECRYPTED: ");
        for (int value : decrypted) {
            sDes.printBytes(value, 8);
            System.out.print(" ");
        }

        StringBuilder builder = new StringBuilder();
        for (int d : decrypted) {
            builder.append(Character.toString((char) d));
        }

        System.out.println("");
        System.out.println("DECRYPTED TEXT: " + builder.toString());
        // bytes.forEach(System.out::println);

        /*
        System.out.println("");
        System.out.println("DECRYPTED MESSAGE: ");
        for (String s : split) {
            int code = Integer.parseInt(s, 2);
        }
        */

        /*
        System.out.println("Enter 10 bit key: ");
        Scanner in = new Scanner(System.in);
        String keyInput = in.nextLine();
        int key = Integer.parseInt(keyInput, 2);

        System.out.println("Enter ENCRYPTED MESSAGE: ");
        int input = Integer.parseInt(in.nextLine(), 2);
        // String input = in.nextLine();

        String encryptedMessage = in.nextLine();
        String[] split = encryptedMessage.split("\\\\s+");
        System.out.println("SPLIT ENCRYPTED: ");
        for (String s : split) {
            System.out.print(s + " ");
        }


        SDes sDes = new SDes(key);

        int encrypted = sDes.process(input, false);

        System.out.println("DECRYPTED: ");
        sDes.printBytesOld(encrypted, 8);
        System.out.println();
        */
    }

    private static String readKey() {
        try {
            URL url = Resources.class.getClassLoader().getResource("key.txt");
            assert url != null;
            BufferedReader bufferedReader = new BufferedReader(
                    new FileReader(url.getPath()));
            String currentLine, input = null;
            while ((currentLine = bufferedReader.readLine()) != null) {
                input = currentLine;
            }

            assert input != null;
            return input;
            //return Integer.parseInt(input, 2);
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    private static String[] readEncryptedStrings() {
        try {
            URL url = Resources.class.getClassLoader().getResource("encrypted.txt");
            assert url != null;
            BufferedReader bufferedReader = new BufferedReader(
                    new FileReader(url.getPath()));
            String currentLine;
            StringBuilder inputBuilder = new StringBuilder();

            while ((currentLine = bufferedReader.readLine()) != null) {
                inputBuilder.append(currentLine);
            }

            return inputBuilder.toString().split("\\s+");
            //return inputBuilder.toString().split("\\\\s+");
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
}
