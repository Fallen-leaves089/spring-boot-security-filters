package io.github.fallenleaves089.security.filters;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MagicBytesValidatorTest {

    @Test
    void shouldAcceptPngSignature() {
        byte[] png = {(byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0};
        assertTrue(MagicBytesValidator.matches("png", new ByteArrayInputStream(png)));
    }

    @Test
    void shouldRejectMismatchedExtension() {
        byte[] text = "not-an-image".getBytes();
        assertFalse(MagicBytesValidator.matches("png", new ByteArrayInputStream(text)));
    }

    @Test
    void shouldReportUnsupportedExtension() {
        assertFalse(MagicBytesValidator.isSupportedExtension("exe"));
    }
}
