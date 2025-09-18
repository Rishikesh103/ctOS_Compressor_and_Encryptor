package org.example.PackerUnpacker;

import java.io.File; // Import the File class
import java.util.Scanner;
// Make sure you have the corrected MainUnpacker in this package
// import PackerUnpacker.MainUnpacker;

public class Unpacker {
    public static void main(String[] args) {
        try {
            Scanner sobj = new Scanner(System.in);

            System.out.println("Enter the name of the file which contains packed data:");
            String packName = sobj.nextLine();

            // --- NEW LOGIC: Input Validation ---
            File sourceFile = new File(packName);
            if (!sourceFile.exists() || !sourceFile.isFile()) {
                System.out.println("[ERROR] The specified source file does not exist or is not a valid file. Aborting.");
                sobj.close();
                return; // Exit the program
            }

            System.out.println("Enter the destination directory to unpack files into:");
            String destDir = sobj.nextLine();

            // --- NEW LOGIC: Destination Validation ---
            File destDirFile = new File(destDir);
            if (destDirFile.exists() && !destDirFile.isDirectory()) {
                System.out.println("[ERROR] The specified destination path exists but is a file, not a directory. Aborting.");
                sobj.close();
                return; // Exit the program
            }


            System.out.println("Enter the password to decrypt the file:");
            String passwordStr = sobj.nextLine();
            if (passwordStr.isEmpty()) {
                System.out.println("[ERROR] Password cannot be empty. Aborting.");
                sobj.close();
                return; // Exit the program
            }

            // 1. Create the MainUnpacker object using the default constructor.
            MainUnpacker mobj = new MainUnpacker();

            // 2. Call the 'unpack' method with the arguments in the correct order.
            //    (Source File, Destination Directory, Password)
            mobj.unpack(packName, destDir, passwordStr.toCharArray());

            System.out.println("\nUnpacking completed successfully.");

            sobj.close();
        } catch (Exception eobj) {
            System.out.println("\nAn error occurred in the Unpacker application. Please check the password or if the file is corrupted.");
            eobj.printStackTrace();
        }
    }
}