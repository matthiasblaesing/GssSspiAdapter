
package eu.doppel_helix.dev.kerberostest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;


public class SSPICommon {

    private static final String[] hexDigits = new String[]{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

    public static void printHexDump(byte[] data) {
        printHexDump(System.out, data);
    }
    
    public static void printHexDump(PrintStream output, byte[] data) {
        output.println("Length: " + data.length + " bytes");
        StringBuilder rowBuffer = new StringBuilder(100);
        for (int rowOffset = 0; rowOffset < data.length; rowOffset += 16) {
            rowBuffer.append(String.format("%04x | ", rowOffset));
            for (int i = 0; i < 16; i++) {
                if ((rowOffset + i) < data.length) {
                    byte dataElement = data[rowOffset + i];
                    rowBuffer.append(hexDigits[(dataElement >> 4) & 0x0F]);
                    rowBuffer.append(hexDigits[dataElement & 0x0F]);
                } else {
                    rowBuffer.append("  ");
                }
                if (i == 7) {
                    rowBuffer.append(":");
                } else {
                    rowBuffer.append(" ");
                }
            }
            rowBuffer.append(" | ");
            for (int i = 0; i < 16; i++) {
                if ((rowOffset + i) < data.length) {
                    char c = (char) data[rowOffset + i];
                    if (Character.isWhitespace(c) || c == 0) {
                        rowBuffer.append(" ");
                    } else {
                        rowBuffer.append(c);
                    }
                }
            }
            output.println(rowBuffer.toString());
            rowBuffer.setLength(0);
        }
    }
    
    public static String toHexDump(byte[] data) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream(data.length * 5);
                PrintStream pw = new PrintStream(baos, true, "UTF-8")) {
            printHexDump(pw, data);
            return baos.toString();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
    
    public static boolean SEC_SUCCESS(int status) {
        return status >= 0;
    }
}
