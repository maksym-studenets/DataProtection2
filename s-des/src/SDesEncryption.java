import com.google.common.io.Resources;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.util.Scanner;

/**
 * Main method for the S-DES encryption algorithm implementation
 */
public class SDesEncryption {

    private static String input;

    public static void main(String[] args) throws Exception {
        readFile();
        System.out.println("Input sequence: " + input);

        System.out.println("Enter 10 bit key: ");
        Scanner in = new Scanner(System.in);
        int key = Integer.parseInt(in.nextLine(), 2);

        SDes sDes = new SDes(key);

        byte[] textBytes = input.getBytes();
        StringBuilder binary = new StringBuilder();
        for (byte element : textBytes) {
            int value = element;
            for (int i = 0; i < 8; i++) {
                binary.append((value & 128) == 0 ? 0 : 1);
                value <<= 1;
            }
            binary.append(" ");
        }

        System.out.println("INPUT BINARY: ");
        System.out.println(binary.toString());

        String[] array = binary.toString().split(" ");
        int[] encrypted = new int[array.length];
        for (int i = 0; i < array.length; i++) {
            int input = Integer.parseInt(array[i], 2);
            encrypted[i] = sDes.process(input, true);
        }


        System.out.println("");
        System.out.println("ENCRYPTED: ");
        for (int value : encrypted) {
            sDes.printBytes(value, 8);
            System.out.print(" ");
        }

        StringBuilder builder = new StringBuilder();
        for (int e : encrypted) {
            builder.append(Character.toString((char) e));
        }

        System.out.println("");
        System.out.println("ENCRYPTED TEXT: " + builder.toString());

        String encryptedString = sDes.getEncryptedMessage(encrypted);
        writeKeyToFile(sDes.get10BitValues(key));
        writeEncryptedToFile(encryptedString);
    }

    private static void readFile() {
        try {
            URL url = Resources.class.getClassLoader().getResource("input.txt");
            assert url != null;
            BufferedReader bufferedReader = new BufferedReader(
                    new FileReader(url.getPath()));
            String currentLine;
            StringBuilder inputBuilder = new StringBuilder();

            while ((currentLine = bufferedReader.readLine()) != null) {
                inputBuilder.append(currentLine);
            }

            input = inputBuilder.toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void writeKeyToFile(String key) {
        try {
            File file = new File("D:\\Progs\\JAVA\\2017\\2\\DataProtection2\\" +
                    "s-des\\res\\key.txt");
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write(key);
            fileWriter.flush();
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void writeEncryptedToFile(String message) {
        try {
            File file = new File("D:\\Progs\\JAVA\\2017\\2\\DataProtection2\\" +
                    "s-des\\res\\encrypted.txt");
            FileWriter fileWriter = new FileWriter(file);
            fileWriter.write(message);
            fileWriter.flush();
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
