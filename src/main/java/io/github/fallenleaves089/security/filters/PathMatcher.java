package io.github.fallenleaves089.security.filters;

import jakarta.servlet.http.HttpServletRequest;

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
     * Returns the application-relative request path. Servlet applications
     * configured with {@code server.servlet.context-path} otherwise see the
     * context prefix in {@link HttpServletRequest#getRequestURI()}.
     */
    static String requestPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        if (uri == null || uri.isEmpty()) {
            return "/";
        }
        String contextPath = request.getContextPath();
        if (contextPath != null
                && !contextPath.isEmpty()
                && !"/".equals(contextPath)
                && (uri.equals(contextPath) || uri.startsWith(contextPath + "/"))) {
            String stripped = uri.substring(contextPath.length());
            return stripped.isEmpty() ? "/" : stripped;
        }
        return uri;
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
