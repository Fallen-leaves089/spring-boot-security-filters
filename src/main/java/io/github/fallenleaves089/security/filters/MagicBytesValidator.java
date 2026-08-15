package io.github.fallenleaves089.security.filters;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Set;

/**
 * Validates file signatures (magic bytes) against common image/video extensions.
 */
public final class MagicBytesValidator {

    private static final Map<String, byte[][]> MAGIC_BYTES = Map.ofEntries(
            Map.entry("jpg", new byte[][]{{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF}}),
            Map.entry("jpeg", new byte[][]{{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF}}),
            Map.entry("png", new byte[][]{{(byte) 0x89, 0x50, 0x4E, 0x47}}),
            Map.entry("gif", new byte[][]{{0x47, 0x49, 0x46, 0x38}}),
            Map.entry("webp", new byte[][]{{0x52, 0x49, 0x46, 0x46}}),
            Map.entry("bmp", new byte[][]{{0x42, 0x4D}}),
            Map.entry("mp4", new byte[][]{{(byte) 0x00, (byte) 0x00, (byte) 0x00}}),
            Map.entry("mov", new byte[][]{{(byte) 0x00, (byte) 0x00, (byte) 0x00}}),
            Map.entry("avi", new byte[][]{{0x52, 0x49, 0x46, 0x46}}),
            Map.entry("webm", new byte[][]{{0x1A, 0x45, (byte) 0xDF, (byte) 0xA3}}),
            Map.entry("mkv", new byte[][]{{0x1A, 0x45, (byte) 0xDF, (byte) 0xA3}}),
            Map.entry("flv", new byte[][]{{0x46, 0x4C, 0x56, 0x01}})
    );

    private static final int READ_LEN = 12;
    private static final Set<String> VIDEO_EXTENSIONS = Set.of("mp4", "mov", "avi", "webm", "mkv", "flv");

    private MagicBytesValidator() {
    }

    public static boolean isSupportedExtension(String extension) {
        return extension != null && MAGIC_BYTES.containsKey(extension.toLowerCase());
    }

    public static boolean isVideoExtension(String extension) {
        return extension != null && VIDEO_EXTENSIONS.contains(extension.toLowerCase());
    }

    public static boolean matches(String extension, InputStream input) {
        String ext = extension == null ? "" : extension.toLowerCase();
        byte[][] signatures = MAGIC_BYTES.get(ext);
        if (signatures == null) {
            return false;
        }
        try {
            byte[] header = new byte[READ_LEN];
            int read = input.read(header);
            if (read <= 0) {
                return false;
            }
            if ("mp4".equals(ext) || "mov".equals(ext)) {
                return read >= 8 && header[4] == 'f' && header[5] == 't' && header[6] == 'y' && header[7] == 'p';
            }
            if ("webp".equals(ext)) {
                return read >= 12 && matchesSignature(header, 0, signatures[0])
                        && header[8] == 'W' && header[9] == 'E' && header[10] == 'B' && header[11] == 'P';
            }
            if ("avi".equals(ext)) {
                return read >= 12 && matchesSignature(header, 0, signatures[0])
                        && header[8] == 'A' && header[9] == 'V' && header[10] == 'I' && header[11] == ' ';
            }
            for (byte[] signature : signatures) {
                if (signature.length <= read && matchesSignature(header, 0, signature)) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return false;
        }
    }

    private static boolean matchesSignature(byte[] header, int offset, byte[] signature) {
        for (int i = 0; i < signature.length; i++) {
            if (header[offset + i] != signature[i]) {
                return false;
            }
        }
        return true;
    }
}
