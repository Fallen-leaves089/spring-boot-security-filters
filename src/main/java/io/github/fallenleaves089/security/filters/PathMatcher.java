package io.github.fallenleaves089.security.filters;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.util.UrlPathHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Small path matcher shared by the filters.
 *
 * <p>Only {@code *} is a wildcard. Every other character is quoted before the
 * pattern is compiled, so paths containing regex metacharacters are safe.</p>
 */
final class PathMatcher {

    private static final UrlPathHelper URL_PATH_HELPER = createPathHelper();

    private final List<String> patterns;
    private final List<Pattern> compiled;

    PathMatcher(List<String> patterns) {
        this.patterns = patterns == null ? List.of() : List.copyOf(patterns);
        List<Pattern> compiledPatterns = new ArrayList<>(this.patterns.size());
        for (String pattern : this.patterns) {
            compiledPatterns.add(compile(pattern));
        }
        this.compiled = List.copyOf(compiledPatterns);
    }

    /**
     * Matches a complete path against a pattern list and returns the matching
     * source pattern, or {@code null} when nothing matches.
     */
    String match(String path) {
        for (int i = 0; i < compiled.size(); i++) {
            if (compiled.get(i).matcher(path).matches()) {
                return patterns.get(i);
            }
        }
        return null;
    }

    /**
     * Matches a path against a prefix-style list. A pattern without {@code *}
     * protects the path itself and its descendants on a segment boundary, so
     * {@code /admin} protects {@code /admin/users} but not
     * {@code /administrator}. A pattern containing {@code *} is matched as a
     * complete glob.
     */
    boolean matchesPrefix(String path) {
        for (int i = 0; i < patterns.size(); i++) {
            String pattern = patterns.get(i);
            if (pattern.indexOf('*') >= 0) {
                if (compiled.get(i).matcher(path).matches()) {
                    return true;
                }
            } else if (isSegmentPrefix(path, pattern)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns the application-relative request path with matrix parameters
     * removed. The request URI must not be used directly for security
     * matching: containers can route paths such as
     * {@code /admin;foo/users} to the same handler as {@code /admin/users}.
     */
    static String requestPath(HttpServletRequest request) {
        String path = URL_PATH_HELPER.getPathWithinApplication(request);
        if (path == null || path.isEmpty()) {
            return "/";
        }
        // UrlPathHelper removes semicolon content before decoding the URI.
        // Remove it again so encoded variants such as %3B are normalized too.
        path = URL_PATH_HELPER.removeSemicolonContent(path);
        return path.isEmpty() ? "/" : path;
    }

    private static UrlPathHelper createPathHelper() {
        UrlPathHelper helper = new UrlPathHelper();
        helper.setRemoveSemicolonContent(true);
        helper.setUrlDecode(true);
        return helper;
    }

    private static boolean isSegmentPrefix(String path, String prefix) {
        if ("/".equals(prefix)) {
            return path.startsWith("/");
        }
        if (path.equals(prefix)) {
            return true;
        }
        String normalized = prefix.length() > 1 && prefix.endsWith("/")
                ? prefix.substring(0, prefix.length() - 1)
                : prefix;
        return path.equals(normalized) || path.startsWith(normalized + "/");
    }

    private static Pattern compile(String source) {
        StringBuilder regex = new StringBuilder("^");
        int literalStart = 0;
        for (int i = 0; i < source.length(); i++) {
            if (source.charAt(i) == '*') {
                regex.append(Pattern.quote(source.substring(literalStart, i))).append(".*");
                literalStart = i + 1;
            }
        }
        regex.append(Pattern.quote(source.substring(literalStart))).append('$');
        return Pattern.compile(regex.toString());
    }
}
