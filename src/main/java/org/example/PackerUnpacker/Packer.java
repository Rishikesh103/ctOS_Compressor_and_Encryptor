package org.example.PackerUnpacker;

import java.io.File;
import java.util.Scanner;

public class Packer {
    public static void main(String[] args) {
        try {
            Scanner sobj = new Scanner(System.in);

            System.out.println("Enter the name of the directory that you want to pack:");
            String dirName = sobj.nextLine();

            File sourceDir = new File(dirName);
            if (!sourceDir.exists() || !sourceDir.isDirectory()) {
                System.out.println("[ERROR] The specified source is not a valid directory. Aborting.");
                sobj.close();
                return;
            }

            System.out.println("Enter the name of the file that you want to create for packing:");
            String packName = sobj.nextLine();

            File destFile = new File(packName);
            if (destFile.exists()) {
                System.out.print("Warning: The file '" + packName + "' already exists. Overwrite? (y/n): ");
                String confirmation = sobj.nextLine().toLowerCase();
                if (!confirmation.equals("y")) {
                    System.out.println("Operation cancelled by user.");
                    sobj.close();
                    return;
                }
            }

            System.out.println("Enter the password to secure the file:");
            String passwordStr = sobj.nextLine();
            if (passwordStr.isEmpty()) {
                System.out.println("[ERROR] Password cannot be empty. Aborting.");
                sobj.close();
                return;
            }

            // --- NEW: Ask for compression level ---
            System.out.println("Enter compression level (Normal, Maximum, Fastest):");
            String compressionLevel = sobj.nextLine();


            MainPacker mobj = new MainPacker();

            // --- FIX: Pass the compressionLevel as the fourth argument ---
            mobj.pack(dirName, packName, passwordStr.toCharArray(), compressionLevel);

            System.out.println("\nPacking completed successfully.");

            sobj.close();
        } catch (Exception eobj) {
            System.out.println("\nAn error occurred during the Packer application.");
            eobj.printStackTrace();
        }
    }
}