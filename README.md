# DedSec Packer: High-Performance File Archiver

A custom-built, multi-featured desktop application developed in Java for bundling, encrypting, and compressing large files and directories, all wrapped in a unique, "hacker-themed" graphical user interface inspired by Watch Dogs 2.

This project was built from the ground up and architected to handle modern, large-scale file operations efficiently, securely, and in parallel.

<img width="1919" height="1079" alt="Screenshot 2025-09-18 172738" src="https://github.com/user-attachments/assets/0c381c49-b0aa-46c0-a6e1-f4984aa25820" />




---<img width="1919" he<img width="1919" height="543" alt="Screenshot 2025-08-10 222208" src="https://github.com/user-attachments/assets/d38f15aa-fe32-4f9c-927b-ff3fb3a269ab" />
ight="1079" alt="Screenshot 2025-08-09 231821" src="https://github.com/user-attachments/assets/622aac6d-d848-4ed1-81a2-2e74af8be3cc" />


## Final Architecture: A Multithreaded Assembly Line

To achieve maximum performance on modern multi-core CPUs, the application's core logic was re-architected to use a **three-thread producer-consumer model**. This creates a parallel "assembly line" for the packing and unpacking process.

Instead of one worker doing everything in sequence (Read -> Compress -> Encrypt -> Write), three specialized threads work simultaneously:

1.  **The Reader Thread (Producer):** Its only job is to read raw data from the source file in chunks and place them into a thread-safe queue.
2.  **The Processor Thread (Consumer/Producer):** It takes a raw chunk from the first queue, **compresses and encrypts** it, and then places the processed data into a second queue.
3.  **The Writer Thread (Consumer):** Its only job is to take the final, processed chunks from the second queue and write them to the destination archive file.

This model is incredibly efficient because while the slow hard drive is being read, the CPU is already processing the previous chunk, and the hard drive is simultaneously writing the chunk before that.

---

## Key Features

* **High-Performance Multithreading:** Utilizes a producer-consumer model to parallelize disk I/O and CPU-intensive tasks, dramatically increasing packing and unpacking speed.
* **Efficient Compression:** Integrates the high-performance **Zstandard (Zstd)** compression library for an industry-leading balance of speed and compression ratio.
* **Military-Grade Security:** Implements modern **AES-256 GCM** authenticated encryption to ensure data integrity and confidentiality. Passwords are never stored directly; instead, a secure key is derived using a random **salt** and **PBKDF2**.
* **Robust Streaming:** Engineered with a true streaming pipeline to handle files of any size with minimal and constant memory usage, permanently solving all `OutOfMemoryError` and 2GB file-size limitations.
* **Custom Themed GUI:** A fully custom graphical user interface built with Java Swing, featuring a unique "DedSec" theme, a real-time "Activity Log", drag-and-drop support, a password strength meter, and a fully functional archive content viewer.
* **Cross-Platform:** Built with Java and packaged using `jpackage`, allowing for the creation of native, platform-friendly installers (`.exe`, `.dmg`, `.deb`/`.rpm`).

---

## Technologies Used

* **Core Language:** Java
* **Concurrency:** Java `ExecutorService` & `BlockingQueue`
* **GUI:** Java Swing
* **Build System:** Apache Maven
* **Encryption:** `javax.crypto` (AES-256 GCM, PBKDF2WithHmacSHA256)
* **Compression:** Zstandard (`zstd-jni` library)
* **UI Theming:** FlatLaf Look and Feel
* **Packaging:** `jpackage` (from JDK)

---

## How to Build and Implement the Final Version

Here are the complete steps and final code to build the high-performance version of the application.

### Step 1: Add the Zstandard Library to `pom.xml`
Add the following dependency to your `pom.xml` file and reload your Maven project.

```xml
<dependency>
    <groupId>com.github.luben</groupId>
    <artifactId>zstd-jni</artifactId>
    <version>1.5.6-2</version>
</dependency>
