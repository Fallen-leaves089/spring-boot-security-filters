package io.github.fallenleaves089.security.filters;

import jakarta.servlet.http.HttpServletRequest;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Immutable client-IP resolver shared by {@link RealIpFilter} and {@link RateLimitFilter}.
 * <p>
 * {@code X-Forwarded-For} is trusted only when the direct peer is in the configured
 * proxy allowlist. Hops are read from right to left, so a client cannot win by
 * prepending a forged address to the header.
 */
public final class ClientIpResolver {

    private static final Pattern IPV4_WITH_PORT =
            Pattern.compile("^(\\d{1,3}(?:\\.\\d{1,3}){3}):(\\d{1,5})$");
    private static final Pattern BRACKETED_IPV6 =
            Pattern.compile("^\\[([^\\]]+)](?::(\\d{1,5}))?$");
    private static final Pattern IPV6_LITERAL = Pattern.compile("^[0-9A-Fa-f:.]+$");

    /** Loopback-only default. Other private ranges must be opted in explicitly. */
    public static final List<String> DEFAULT_TRUSTED_PROXIES =
            List.of("127.0.0.0/8", "::1/128");

    private static final ClientIpResolver DEFAULT_RESOLVER =
            new ClientIpResolver(true, DEFAULT_TRUSTED_PROXIES);

    private final boolean enabled;
    private final List<CidrRange> trustedProxies;

    public ClientIpResolver(SecurityFiltersProperties.RealIp properties) {
        this(properties.isEnabled(), properties.getTrustedProxies());
    }

    public ClientIpResolver(boolean enabled, List<String> trustedProxies) {
        this.enabled = enabled;
        Objects.requireNonNull(trustedProxies, "trustedProxies must not be null");
        List<CidrRange> ranges = new ArrayList<>(trustedProxies.size());
        for (String trustedProxy : trustedProxies) {
            ranges.add(parseCidr(trustedProxy));
        }
        this.trustedProxies = Collections.unmodifiableList(ranges);
    }

    public static ClientIpResolver defaults() {
        return DEFAULT_RESOLVER;
    }

    public String resolve(HttpServletRequest request) {
        String remoteAddress = normalize(request.getRemoteAddr());
        if (!enabled) {
            return remoteAddress;
        }

        Object attribute = request.getAttribute(RealIpFilter.ATTR_REAL_IP);
        if (attribute != null) {
            return attribute.toString();
        }

        if (!isTrustedProxy(remoteAddress)) {
            return remoteAddress;
        }

        List<String> headerValues = Collections.list(request.getHeaders("X-Forwarded-For"));
        for (int headerIndex = headerValues.size() - 1; headerIndex >= 0; headerIndex--) {
            String[] hops = headerValues.get(headerIndex).split(",", -1);
            for (int hopIndex = hops.length - 1; hopIndex >= 0; hopIndex--) {
                String hop = normalize(hops[hopIndex]);
                ParsedAddress parsedHop = parseAddress(hop);
                if (parsedHop == null) {
                    return remoteAddress;
                }
                if (!isTrustedProxy(parsedHop)) {
                    return hop;
                }
            }
        }
        return remoteAddress;
    }

    static String normalize(String ip) {
        if (ip == null) {
            return "";
        }
        String value = ip.trim();

        Matcher ipv6WithPort = BRACKETED_IPV6.matcher(value);
        if (ipv6WithPort.matches()) {
            if (isValidPort(ipv6WithPort.group(2))) {
                return ipv6WithPort.group(1);
            }
            return value;
        }

        Matcher ipv4WithPort = IPV4_WITH_PORT.matcher(value);
        if (ipv4WithPort.matches() && isValidPort(ipv4WithPort.group(2))) {
            return ipv4WithPort.group(1);
        }
        return value;
    }

    private boolean isTrustedProxy(String ip) {
        ParsedAddress address = parseAddress(ip);
        return address != null && isTrustedProxy(address);
    }

    private boolean isTrustedProxy(ParsedAddress address) {
        for (CidrRange range : trustedProxies) {
            if (range.contains(address.bytes)) {
                return true;
            }
        }
        return false;
    }

    private static ParsedAddress parseAddress(String value) {
        if (value == null) {
            return null;
        }

        String candidate = value.trim();
        if (candidate.startsWith("[") && candidate.endsWith("]")) {
            candidate = candidate.substring(1, candidate.length() - 1);
        }

        if (candidate.isEmpty()) {
            return null;
        }
        if (candidate.indexOf(':') >= 0) {
            if (!IPV6_LITERAL.matcher(candidate).matches()) {
                return null;
            }
        } else if (!isValidIpv4Literal(candidate)) {
            return null;
        }

        try {
            byte[] address = InetAddress.getByName(candidate).getAddress();
            if (address.length == 16 && isIpv4Mapped(address)) {
                address = Arrays.copyOfRange(address, 12, 16);
            }
            return new ParsedAddress(address);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    private static boolean isValidIpv4Literal(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.charAt(0) == '0')) {
                return false;
            }
            for (int i = 0; i < part.length(); i++) {
                char character = part.charAt(i);
                if (character < '0' || character > '9') {
                    return false;
                }
            }
            if (Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpv4Mapped(byte[] address) {
        for (int i = 0; i < 10; i++) {
            if (address[i] != 0) {
                return false;
            }
        }
        return address[10] == (byte) 0xFF && address[11] == (byte) 0xFF;
    }

    private static boolean isValidPort(String port) {
        return port == null || Integer.parseInt(port) <= 65535;
    }

    private static CidrRange parseCidr(String value) {
        if (value == null || value.isBlank()) {
            throw invalidTrustedProxy(value);
        }

        String candidate = value.trim();
        int slash = candidate.indexOf('/');
        if (slash != candidate.lastIndexOf('/')) {
            throw invalidTrustedProxy(value);
        }

        String addressPart = slash < 0 ? candidate : candidate.substring(0, slash);
        ParsedAddress network = parseAddress(addressPart);
        if (network == null) {
            throw invalidTrustedProxy(value);
        }

        int maxPrefix = network.bytes.length * 8;
        int prefixLength = maxPrefix;
        if (slash >= 0) {
            String prefixPart = candidate.substring(slash + 1);
            if (prefixPart.isEmpty()) {
                throw invalidTrustedProxy(value);
            }
            for (int i = 0; i < prefixPart.length(); i++) {
                char character = prefixPart.charAt(i);
                if (character < '0' || character > '9') {
                    throw invalidTrustedProxy(value);
                }
            }
            try {
                prefixLength = Integer.parseInt(prefixPart);
            } catch (NumberFormatException e) {
                throw invalidTrustedProxy(value);
            }
            if (prefixLength > maxPrefix) {
                throw invalidTrustedProxy(value);
            }
        }
        return new CidrRange(network.bytes, prefixLength);
    }

    private static IllegalArgumentException invalidTrustedProxy(String value) {
        return new IllegalArgumentException(
                "security.real-ip.trusted-proxies must contain only IP or CIDR literals: " + value);
    }

    private static final class ParsedAddress {
        private final byte[] bytes;

        private ParsedAddress(byte[] bytes) {
            this.bytes = bytes;
        }
    }

    private static final class CidrRange {
        private final byte[] network;
        private final int prefixLength;

        private CidrRange(byte[] network, int prefixLength) {
            this.network = network;
            this.prefixLength = prefixLength;
        }

        private boolean contains(byte[] address) {
            if (address.length != network.length) {
                return false;
            }
            int fullBytes = prefixLength / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (address[i] != network[i]) {
                    return false;
                }
            }
            int remainingBits = prefixLength % 8;
            if (remainingBits == 0) {
                return true;
            }
            int mask = 0xFF << (8 - remainingBits);
            return (address[fullBytes] & mask) == (network[fullBytes] & mask);
        }
    }
}
