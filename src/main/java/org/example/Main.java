package org.example;
import org.example.PackerUnpacker.MainPacker;
import org.example.PackerUnpacker.MainUnpacker;

import com.formdev.flatlaf.FlatDarkLaf;
import javax.sound.sampled.*;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.dnd.DnDConstants;
import java.awt.dnd.DropTarget;
import java.awt.dnd.DropTargetDropEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class Main {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            ResourceLoader.load();
            new MainFrame().setVisible(true);
        });
    }
}

class ResourceLoader {
    public static Font hackedFont;
    public static Image backgroundImage;
    public static Cursor customCursor;
    private static Clip musicClip;

    public static void load() {
        hackedFont = loadFont("/hacked.ttf");
        backgroundImage = loadImage("/wd2_background.gif");
        customCursor = loadCursor("/cursor.png");
    }

    private static Font loadFont(String path) {
        try (InputStream in = ResourceLoader.class.getResourceAsStream(path)) {
            if (in == null) throw new IOException("Font not found: " + path);
            Font font = Font.createFont(Font.TRUETYPE_FONT, in);
            GraphicsEnvironment.getLocalGraphicsEnvironment().registerFont(font);
            return font;
        } catch (Exception e) {
            e.printStackTrace();
            return new Font("Monospaced", Font.BOLD, 28);
        }
    }

    private static Image loadImage(String path) {
        URL imgUrl = ResourceLoader.class.getResource(path);
        return (imgUrl != null) ? new ImageIcon(imgUrl).getImage() : null;
    }

    private static Cursor loadCursor(String path) {
        try {
            Toolkit toolkit = Toolkit.getDefaultToolkit();
            URL cursorUrl = ResourceLoader.class.getResource(path);
            if (cursorUrl == null) return Cursor.getDefaultCursor();
            Image image = toolkit.getImage(cursorUrl);
            return toolkit.createCustomCursor(image, new Point(0, 0), "custom_cursor");
        } catch (Exception e) {
            return Cursor.getDefaultCursor();
        }
    }

    public static void playSound(String path, float volume, Runnable onFinish) {
        try (AudioInputStream audioIn = AudioSystem.getAudioInputStream(ResourceLoader.class.getResource("/" + path))) {
            Clip clip = AudioSystem.getClip();
            if (onFinish != null) {
                clip.addLineListener(event -> {
                    if (event.getType() == LineEvent.Type.STOP) {
                        clip.close();
                        onFinish.run();
                    }
                });
            }
            clip.open(audioIn);
            FloatControl gainControl = (FloatControl) clip.getControl(FloatControl.Type.MASTER_GAIN);
            float dB = (float) (Math.log(volume) / Math.log(10.0) * 20.0);
            gainControl.setValue(dB);
            clip.start();
        } catch (Exception e) { e.printStackTrace(); }
    }

    public static void playBackgroundMusic(String path, float volume) {
        try (AudioInputStream audioIn = AudioSystem.getAudioInputStream(ResourceLoader.class.getResource("/" + path))) {
            musicClip = AudioSystem.getClip();
            musicClip.open(audioIn);
            FloatControl gainControl = (FloatControl) musicClip.getControl(FloatControl.Type.MASTER_GAIN);
            float dB = (float) (Math.log(volume) / Math.log(10.0) * 20.0);
            gainControl.setValue(dB);
            musicClip.loop(Clip.LOOP_CONTINUOUSLY);
        } catch (Exception e) { e.printStackTrace(); }
    }

    public static void stopBackgroundMusic() {
        if (musicClip != null) musicClip.stop();
    }

    public static void startBackgroundMusic() {
        if (musicClip != null) musicClip.loop(Clip.LOOP_CONTINUOUSLY);
    }
}

class UIFactory {
    public static final Color WD_WHITE = Color.decode("#FFFFFF");
    public static final Color WD_DARK_BLUE = Color.decode("#0A192F");
    public static final Color WD_TEXT = Color.decode("#EAEAEA");

    public static JButton createWatchDogsButton(String text) {
        JButton button = new BlackButton(text);
        button.setFont(new Font("Consolas", Font.BOLD, 24));
        button.setForeground(WD_WHITE);
        button.setFocusPainted(false);
        button.addActionListener(e -> ResourceLoader.playSound("onclick.wav", 0.9f, null));
        return button;
    }

    public static JTextField createWatchDogsTextField() {
        JTextField textField = new JTextField(30);
        textField.setBackground(new Color(10, 25, 47, 200));
        textField.setForeground(WD_TEXT);
        textField.setCaretColor(WD_WHITE);
        textField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        textField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(WD_WHITE, 1),
                BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
        return textField;
    }

    public static JPasswordField createWatchDogsPasswordField() {
        JPasswordField passwordField = new JPasswordField(30);
        passwordField.setBackground(new Color(10, 25, 47, 200));
        passwordField.setForeground(WD_TEXT);
        passwordField.setCaretColor(WD_WHITE);
        passwordField.setFont(new Font("Monospaced", Font.PLAIN, 14));
        passwordField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(WD_WHITE, 1),
                BorderFactory.createEmptyBorder(5, 10, 5, 10)
        ));
        return passwordField;
    }

    public static JLabel createWDLabel(String text) {
        JLabel label = new JLabel(text);
        label.setFont(new Font("Arial", Font.BOLD, 14));
        label.setForeground(WD_TEXT);
        return label;
    }

    public static JComboBox<String> createWatchDogsComboBox(String[] items) {
        JComboBox<String> comboBox = new JComboBox<>(items);
        comboBox.setBackground(WD_DARK_BLUE);
        comboBox.setForeground(WD_TEXT);
        comboBox.setFont(new Font("Monospaced", Font.PLAIN, 14));
        comboBox.setBorder(BorderFactory.createLineBorder(WD_WHITE, 1));
        comboBox.addActionListener(e -> ResourceLoader.playSound("onclick.wav", 0.9f, null));
        return comboBox;
    }

    public static JToggleButton createShowPasswordToggle() {
        JToggleButton toggleButton = new JToggleButton("SHOW");
        toggleButton.setFont(new Font("Consolas", Font.BOLD, 12));
        toggleButton.setForeground(WD_TEXT);
        toggleButton.setBackground(WD_DARK_BLUE);
        toggleButton.setBorder(BorderFactory.createLineBorder(WD_WHITE, 1));
        toggleButton.setFocusPainted(false);
        toggleButton.addActionListener(e -> {
            ResourceLoader.playSound("onclick.wav", 0.9f, null);
            toggleButton.setText(toggleButton.isSelected() ? "HIDE" : "SHOW");
        });
        return toggleButton;
    }
}

class MainFrame extends JFrame {
    private CardLayout cardLayout = new CardLayout();
    private JPanel mainContentPanel = new JPanel(cardLayout);

    public MainFrame() {
        setTitle("DedSec Packer Unpacker");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setUndecorated(true);
        setSize(1024, 768);
        setLocationRelativeTo(null);
        setExtendedState(JFrame.MAXIMIZED_BOTH);

        ResourceLoader.playBackgroundMusic("wd2_theme.wav", 0.85f);

        BackgroundPanel backgroundPanel = new BackgroundPanel();
        backgroundPanel.setLayout(new BorderLayout());
        backgroundPanel.add(new CustomTitleBar(this), BorderLayout.NORTH);

        mainContentPanel.setOpaque(false);
        mainContentPanel.add(new MenuPanel(this), "MENU");
        mainContentPanel.add(new PackerPanel(this), "PACKER");
        mainContentPanel.add(new UnpackerPanel(this), "UNPACKER");
        backgroundPanel.add(mainContentPanel, BorderLayout.CENTER);

        setContentPane(backgroundPanel);
        setCursor(ResourceLoader.customCursor);
    }

    public void showPanel(String panelName) {
        cardLayout.show(mainContentPanel, panelName);
    }
}

class CustomTitleBar extends JPanel {
    private Point initialClick;

    public CustomTitleBar(JFrame parent) {
        setOpaque(false);
        setLayout(new BorderLayout());

        JLabel title = new JLabel(" // DedSec Packer-Unpacker_");
        title.setFont(ResourceLoader.hackedFont.deriveFont(20f));
        title.setForeground(UIFactory.WD_TEXT);
        add(title, BorderLayout.WEST);

        JButton minimizeButton = createControlButton("_", e -> parent.setState(Frame.ICONIFIED));
        JButton closeButton = createControlButton("X", e -> System.exit(0));

        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        controlPanel.setOpaque(false);
        controlPanel.add(minimizeButton);
        controlPanel.add(closeButton);
        add(controlPanel, BorderLayout.EAST);

        addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) { initialClick = e.getPoint(); }
        });
        addMouseMotionListener(new MouseMotionAdapter() {
            public void mouseDragged(MouseEvent e) {
                int thisX = parent.getLocation().x;
                int thisY = parent.getLocation().y;
                int xMoved = e.getX() - initialClick.x;
                int yMoved = e.getY() - initialClick.y;
                parent.setLocation(thisX + xMoved, thisY + yMoved);
            }
        });
    }

    private JButton createControlButton(String text, java.awt.event.ActionListener action) {
        JButton button = new JButton(text);
        button.setForeground(UIFactory.WD_TEXT);
        button.setFocusPainted(false);
        button.setBorder(BorderFactory.createEmptyBorder(2, 12, 2, 12));
        button.setContentAreaFilled(false);
        button.setFont(new Font("Monospaced", Font.BOLD, 16));
        button.addActionListener(action);
        return button;
    }
}

class BackgroundPanel extends JPanel {
    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        if (ResourceLoader.backgroundImage != null) {
            Graphics2D g2d = (Graphics2D) g.create();
            g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
            g2d.drawImage(ResourceLoader.backgroundImage, 0, 0, getWidth(), getHeight(), this);
            g2d.dispose();
        } else {
            g.setColor(UIFactory.WD_DARK_BLUE);
            g.fillRect(0, 0, getWidth(), getHeight());
        }
    }
}

class BlackButton extends JButton {
    public BlackButton(String text) {
        super(text);
        setContentAreaFilled(false);
        setOpaque(false);
        setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(Color.BLACK);
        g2.fillRect(0, 0, getWidth(), getHeight());
        g2.setColor(new Color(255, 255, 255, 50));
        FontMetrics fm = g2.getFontMetrics();
        int x = (getWidth() - fm.stringWidth(getText())) / 2;
        int y = (getHeight() - fm.getHeight()) / 2 + fm.getAscent();
        g2.drawString(getText(), x - 1, y - 1);
        g2.drawString(getText(), x + 1, y - 1);
        g2.drawString(getText(), x - 1, y + 1);
        g2.drawString(getText(), x + 1, y + 1);
        g2.dispose();
        super.paintComponent(g);
    }
}

class MenuPanel extends JPanel {
    public MenuPanel(MainFrame mainFrame) {
        setOpaque(false);
        setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(20, 10, 20, 10);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JLabel titleLabel = new JLabel("DEDSEC PACKER");
        titleLabel.setFont(ResourceLoader.hackedFont.deriveFont(60f));
        titleLabel.setForeground(UIFactory.WD_TEXT);
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        add(titleLabel, gbc);

        JButton packButton = UIFactory.createWatchDogsButton("Pack Files");
        packButton.addActionListener(e -> mainFrame.showPanel("PACKER"));
        add(packButton, gbc);

        JButton unpackButton = UIFactory.createWatchDogsButton("Unpack Files");
        unpackButton.addActionListener(e -> mainFrame.showPanel("UNPACKER"));
        add(unpackButton, gbc);

        JButton exitButton = UIFactory.createWatchDogsButton("Exit");
        exitButton.addActionListener(e -> System.exit(0));
        add(exitButton, gbc);
    }
}

abstract class AbstractFunctionalPanel extends JPanel {
    protected MainFrame mainFrame;
    protected JTextField field1, field2;
    protected JPasswordField passwordField;
    protected JTextArea statusArea = new JTextArea(10, 50);
    protected JProgressBar progressBar = new JProgressBar();
    protected List<Component> componentsToDisable = new ArrayList<>();

    public AbstractFunctionalPanel(MainFrame frame, String type, String label1Text, String label2Text, String buttonText) {
        this.mainFrame = frame;
        setOpaque(false);
        setLayout(new BorderLayout(20, 20));
        setBorder(BorderFactory.createEmptyBorder(50, 50, 50, 50));

        JLabel titleLabel = new JLabel(type);
        titleLabel.setFont(ResourceLoader.hackedFont.deriveFont(40f));
        titleLabel.setForeground(UIFactory.WD_TEXT);
        titleLabel.setHorizontalAlignment(SwingConstants.CENTER);
        add(titleLabel, BorderLayout.NORTH);

        JPanel fieldsPanel = new JPanel(new GridBagLayout());
        fieldsPanel.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 5, 10, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        field1 = UIFactory.createWatchDogsTextField();
        field2 = UIFactory.createWatchDogsTextField();
        passwordField = UIFactory.createWatchDogsPasswordField();

        setDropTarget(new DropTarget() {
            public synchronized void drop(DropTargetDropEvent evt) {
                try {
                    evt.acceptDrop(DnDConstants.ACTION_COPY);
                    List<File> files = (List<File>) evt.getTransferable().getTransferData(DataFlavor.javaFileListFlavor);
                    if (!files.isEmpty()) field1.setText(files.get(0).getAbsolutePath());
                } catch (Exception ex) { ex.printStackTrace(); }
            }
        });

        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.LINE_END; fieldsPanel.add(UIFactory.createWDLabel(label1Text), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.anchor = GridBagConstraints.LINE_START; fieldsPanel.add(field1, gbc);
        JButton browse1 = UIFactory.createWatchDogsButton("browse");
        browse1.setFont(new Font("Consolas", Font.BOLD, 16));
        gbc.gridx = 2; gbc.weightx = 0; fieldsPanel.add(browse1, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.anchor = GridBagConstraints.LINE_END; fieldsPanel.add(UIFactory.createWDLabel(label2Text), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.anchor = GridBagConstraints.LINE_START; fieldsPanel.add(field2, gbc);
        JButton browse2 = UIFactory.createWatchDogsButton("browse");
        browse2.setFont(new Font("Consolas", Font.BOLD, 16));
        gbc.gridx = 2; gbc.weightx = 0; fieldsPanel.add(browse2, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.anchor = GridBagConstraints.LINE_END; fieldsPanel.add(UIFactory.createWDLabel("Password:"), gbc);
        JPanel passwordPanel = new JPanel(new BorderLayout());
        passwordPanel.setOpaque(false);
        passwordPanel.add(passwordField, BorderLayout.CENTER);
        JToggleButton showPass = UIFactory.createShowPasswordToggle();
        showPass.addActionListener(e -> passwordField.setEchoChar(showPass.isSelected() ? (char) 0 : '•'));
        passwordPanel.add(showPass, BorderLayout.EAST);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.anchor = GridBagConstraints.LINE_START; fieldsPanel.add(passwordPanel, gbc);

        JPanel statusWrapper = new JPanel(new BorderLayout());
        statusWrapper.setOpaque(false);
        Border lineBorder = BorderFactory.createLineBorder(UIFactory.WD_WHITE);
        statusWrapper.setBorder(BorderFactory.createTitledBorder(lineBorder, "ACTIVITY LOG", TitledBorder.LEFT, TitledBorder.TOP, ResourceLoader.hackedFont.deriveFont(16f), UIFactory.WD_WHITE));

        statusArea.setEditable(false);
        statusArea.setFont(new Font("Monospaced", Font.PLAIN, 14));
        statusArea.setForeground(UIFactory.WD_TEXT);
        statusArea.setBackground(new Color(10, 25, 47, 220));
        JScrollPane scrollPane = new JScrollPane(statusArea);
        scrollPane.getViewport().setOpaque(false);
        scrollPane.setOpaque(false);
        statusWrapper.add(scrollPane, BorderLayout.CENTER);

        progressBar.setIndeterminate(true);
        progressBar.setVisible(false);
        statusWrapper.add(progressBar, BorderLayout.SOUTH);

        JPanel centerPanel = new JPanel(new BorderLayout(10, 10));
        centerPanel.setOpaque(false);
        centerPanel.add(fieldsPanel, BorderLayout.NORTH);
        centerPanel.add(statusWrapper, BorderLayout.CENTER);
        add(centerPanel, BorderLayout.CENTER);

        JButton actionButton = UIFactory.createWatchDogsButton(buttonText);
        JButton backButton = UIFactory.createWatchDogsButton("Back");
        backButton.addActionListener(e -> mainFrame.showPanel("MENU"));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 0));
        buttonPanel.setOpaque(false);
        buttonPanel.add(actionButton);
        if (type.equals("UNPACKER")) {
            JButton viewButton = UIFactory.createWatchDogsButton("View Contents");
            buttonPanel.add(viewButton);
        }
        buttonPanel.add(backButton);
        add(buttonPanel, BorderLayout.SOUTH);

        setupActions(browse1, browse2, actionButton, buttonPanel);
        componentsToDisable.addAll(List.of(field1, field2, passwordField, browse1, browse2, actionButton, backButton));
        if (type.equals("UNPACKER")) componentsToDisable.add(buttonPanel.getComponent(1));
    }

    protected void toggleComponents(boolean enabled) {
        componentsToDisable.forEach(c -> c.setEnabled(enabled));
    }

    protected void redirectSystemStreams(JTextArea logArea) {
        logArea.setText("");
        OutputStream out = new OutputStream() {
            @Override
            public void write(int b) {
                SwingUtilities.invokeLater(() -> logArea.append(String.valueOf((char) b)));
            }
        };
        System.setOut(new PrintStream(out, true));
        System.setErr(new PrintStream(out, true));
    }

    protected abstract void setupActions(JButton browse1, JButton browse2, JButton actionButton, JPanel buttonPanel);
}

// In your main GUI file, completely REPLACE the old PackerPanel class with this one.

class PackerPanel extends AbstractFunctionalPanel {
    private JComboBox<String> compressionBox;

    public PackerPanel(MainFrame frame) {
        super(frame, "PACKER", "Select Directory to Pack:", "Save Packed File As:", "Start Packing");

        JPanel fieldsPanel = (JPanel)((JPanel)getComponent(1)).getComponent(0);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(10, 5, 10, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        JProgressBar strengthBar = new JProgressBar(0, 100);
        strengthBar.setStringPainted(true);
        strengthBar.setBackground(new Color(10, 25, 47, 128));
        passwordField.getDocument().addDocumentListener(new DocumentListener() {
            public void changedUpdate(DocumentEvent e) { updateStrength(); }
            public void removeUpdate(DocumentEvent e) { updateStrength(); }
            public void insertUpdate(DocumentEvent e) { updateStrength(); }
            public void updateStrength() {
                char[] pass = passwordField.getPassword();
                int score = 0;
                if (pass.length >= 8) score += 25;
                if (String.valueOf(pass).matches(".*[A-Z].*")) score += 25;
                if (String.valueOf(pass).matches(".*[a-z].*")) score += 25;
                if (String.valueOf(pass).matches(".*[0-9].*")) score += 25;
                strengthBar.setValue(score);
                if (score < 50) { strengthBar.setString("Weak"); strengthBar.setForeground(Color.RED); }
                else if (score < 100) { strengthBar.setString("Medium"); strengthBar.setForeground(Color.ORANGE); }
                else { strengthBar.setString("Strong"); strengthBar.setForeground(Color.GREEN); }
            }
        });
        gbc.gridx = 1; gbc.gridy = 3; fieldsPanel.add(strengthBar, gbc);

        gbc.gridx = 0; gbc.gridy = 4; gbc.anchor = GridBagConstraints.LINE_END; fieldsPanel.add(UIFactory.createWDLabel("Compression:"), gbc);

        // --- FIX: Updated the labels for clarity and to match the backend logic ---
        String[] levels = {"Zstandard (Normal)", "Maximum Compression (Slow)", "Fastest Compression"};
        compressionBox = UIFactory.createWatchDogsComboBox(levels);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.anchor = GridBagConstraints.LINE_START; fieldsPanel.add(compressionBox, gbc);

        componentsToDisable.addAll(List.of(strengthBar, compressionBox));
    }

    @Override
    protected void setupActions(JButton browse1, JButton browse2, JButton actionButton, JPanel buttonPanel) {
        browse1.addActionListener(e -> choosePath(field1, JFileChooser.DIRECTORIES_ONLY, false));
        browse2.addActionListener(e -> choosePath(field2, JFileChooser.FILES_ONLY, true));
        actionButton.addActionListener(e -> performPacking());
    }

    private void performPacking() {
        if (field1.getText().isEmpty() || field2.getText().isEmpty() || passwordField.getPassword().length == 0) {
            JOptionPane.showMessageDialog(this, "All fields are required.", "Input Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        String selectedLevel = (String) compressionBox.getSelectedItem();

        redirectSystemStreams(statusArea);
        new BackgroundTask(this) {
            protected Void doInBackground() throws Exception {
                new MainPacker().pack(field1.getText(), field2.getText(), passwordField.getPassword(), selectedLevel);
                return null;
            }
        }.execute();
    }

    private void choosePath(JTextField targetField, int selectionMode, boolean isSaveDialog) {
        try {
            UIManager.setLookAndFeel(new FlatDarkLaf());
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(selectionMode);

            int result;
            if (isSaveDialog) {
                result = chooser.showSaveDialog(this);
            } else {
                result = chooser.showOpenDialog(this);
            }

            if (result == JFileChooser.APPROVE_OPTION) {
                targetField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
            SwingUtilities.updateComponentTreeUI(mainFrame);
        } catch (Exception ex) { ex.printStackTrace(); }
    }
}

class UnpackerPanel extends AbstractFunctionalPanel {
    public UnpackerPanel(MainFrame frame) {
        super(frame, "UNPACKER", "Select Packed File:", "Unpack to Directory:", "Start Unpacking");
    }

    @Override
    protected void setupActions(JButton browse1, JButton browse2, JButton actionButton, JPanel buttonPanel) {
        browse1.addActionListener(e -> choosePath(field1, JFileChooser.FILES_ONLY, false));
        browse2.addActionListener(e -> choosePath(field2, JFileChooser.DIRECTORIES_ONLY, false));
        actionButton.addActionListener(e -> performUnpacking());

        JButton viewButton = (JButton) buttonPanel.getComponent(1);
        viewButton.addActionListener(e -> performViewContents());
    }

    private void performViewContents() {
        if (field1.getText().isEmpty() || passwordField.getPassword().length == 0) {
            redirectSystemStreams(statusArea);
            System.err.println("// ERROR: SOURCE PAYLOAD AND PASSWORD ARE REQUIRED FOR ANALYSIS.");
            return;
        }

        JDialog progressDialog = new JDialog(mainFrame, "ANALYZING PAYLOAD...", true);
        progressDialog.setSize(300, 75);
        progressDialog.setLocationRelativeTo(mainFrame);
        JProgressBar pBar = new JProgressBar();
        pBar.setIndeterminate(true);
        progressDialog.add(pBar);

        new SwingWorker<List<String>, Void>() {
            protected List<String> doInBackground() throws Exception {
                return new MainUnpacker().listContents(field1.getText(), passwordField.getPassword());
            }

            @Override
            protected void done() {
                progressDialog.dispose();
                redirectSystemStreams(statusArea);
                try {
                    List<String> contents = get();
                    System.out.println("// ARCHIVE SCAN COMMENCED...");
                    System.out.println("// PAYLOAD: " + field1.getText());
                    System.out.println("----------------------------------------------");
                    for (String line : contents) {
                        System.out.println(" " + line);
                    }
                    System.out.println("----------------------------------------------");
                    System.out.println("// ANALYSIS COMPLETE. " + contents.size() + " OBJECTS IDENTIFIED.");
                    System.out.println("// STANDING BY FOR FURTHER DIRECTIVES.");
                } catch (Exception ex) {
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    System.err.println("// ERROR: ARCHIVE ANALYSIS FAILED.");
                    if (cause instanceof java.io.EOFException) {
                        System.err.println("// REASON: UNEXPECTED END OF FILE. THE ARCHIVE MAY BE INCOMPLETE OR CORRUPTED.");
                    } else if (cause instanceof javax.crypto.AEADBadTagException || cause instanceof javax.crypto.BadPaddingException) {
                        System.err.println("// REASON: AUTHENTICATION TAG MISMATCH. PASSWORD INVALID OR PAYLOAD CORRUPTED.");
                    } else {
                        System.err.println("// REASON: " + (cause.getMessage() != null ? cause.getMessage().toUpperCase() : "UNKNOWN FAULT"));
                    }
                }
            }
        }.execute();
        progressDialog.setVisible(true);
    }

    private void performUnpacking() {
        if (field1.getText().isEmpty() || field2.getText().isEmpty() || passwordField.getPassword().length == 0) {
            redirectSystemStreams(statusArea);
            System.err.println("// ERROR: ALL FIELDS REQUIRED FOR EXTRACTION.");
            return;
        }
        redirectSystemStreams(statusArea);
        new BackgroundTask(this) {
            protected Void doInBackground() throws Exception {
                new MainUnpacker().unpack(field1.getText(), field2.getText(), passwordField.getPassword());
                return null;
            }
        }.execute();
    }

    private void choosePath(JTextField targetField, int selectionMode, boolean isSaveDialog) {
        try {
            UIManager.setLookAndFeel(new FlatDarkLaf());
            JFileChooser chooser = new JFileChooser();
            chooser.setFileSelectionMode(selectionMode);
            if (isSaveDialog) {
                if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
                    targetField.setText(chooser.getSelectedFile().getAbsolutePath());
                }
            } else {
                if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                    targetField.setText(chooser.getSelectedFile().getAbsolutePath());
                }
            }

            SwingUtilities.updateComponentTreeUI(mainFrame);
        } catch (Exception ex) { ex.printStackTrace(); }
    }
}

abstract class BackgroundTask extends SwingWorker<Void, Void> {
    private AbstractFunctionalPanel panel;

    public BackgroundTask(AbstractFunctionalPanel panel) {
        this.panel = panel;
        panel.toggleComponents(false);
        panel.progressBar.setVisible(true);
    }

    @Override
    protected void done() {
        panel.toggleComponents(true);
        panel.progressBar.setVisible(false);

        try {
            get();
            System.out.println("\n\n// Operation completed successfully_");
            ResourceLoader.playSound("success.wav", 0.8f, null);
        } catch (Exception e) {
            // This is the updated error logging
            System.err.println("\n\n// OPERATION FAILED. INITIATING DIAGNOSTIC REPORT...");
            System.err.println("-------------------------------------------------");
            e.printStackTrace(System.err); // This prints the full error
            System.err.println("-------------------------------------------------");
            ResourceLoader.playSound("onclick.wav", 0.9f, null);
        }
    }
}