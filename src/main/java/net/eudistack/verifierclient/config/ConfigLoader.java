package net.eudistack.verifierclient.config;

import net.eudistack.verifierclient.exception.InvalidConfigurationException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;

/**
 * Loads a {@link VerifierM2MClientConfig} from a {@code .yaml}/{@code .yml} or
 * {@code .properties} file.
 *
 * <p>Recognised keys (both formats use the same dotted names). {@code verifier.url} is the
 * remote service you're connecting to; everything under {@code verifier.client.*} is your
 * own — the private key and credential you're authenticating with, not the Verifier's:
 *
 * <ul>
 *   <li>{@code verifier.url} — the Verifier's base URL
 *   <li>{@code verifier.client.private-key-jwk} — your private key, as an inline JWK JSON string
 *   <li>{@code verifier.client.private-key-jwk-path} — path to a file containing the JWK JSON
 *   <li>{@code verifier.client.credential-jwt} — your machine credential, as an inline JWT string
 *   <li>{@code verifier.client.credential-jwt-path} — path to a file containing the credential JWT
 * </ul>
 *
 * Exactly one of the inline/path variants must be set for the key and for the credential.
 *
 * <p>YAML support requires {@code org.yaml:snakeyaml} on the classpath — it is an optional
 * dependency of this SDK, only needed if {@code .yaml}/{@code .yml} files are loaded.
 */
public final class ConfigLoader {

    private ConfigLoader() {}

    public static VerifierM2MClientConfig load(String path) {
        return load(Path.of(path));
    }

    public static VerifierM2MClientConfig load(Path path) {
        String fileName = path.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        Map<String, Object> raw =
                (fileName.endsWith(".yaml") || fileName.endsWith(".yml"))
                        ? loadYaml(path)
                        : loadProperties(path);
        return toConfig(raw, path);
    }

    private static Map<String, Object> loadProperties(Path path) {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(path)) {
            properties.load(in);
        } catch (IOException e) {
            throw new InvalidConfigurationException("Failed to read config file: " + path, e);
        }
        Map<String, Object> result = new java.util.HashMap<>();
        for (String name : properties.stringPropertyNames()) {
            result.put(name, properties.getProperty(name));
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadYaml(Path path) {
        Object yamlClassProbe;
        try {
            yamlClassProbe = Class.forName("org.yaml.snakeyaml.Yaml").getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException e) {
            throw new InvalidConfigurationException(
                    "Loading a .yaml config file requires 'org.yaml:snakeyaml' on the classpath. "
                            + "Add it as a dependency, or use a .properties file instead.",
                    e);
        }

        try (InputStream in = Files.newInputStream(path)) {
            var loadMethod = yamlClassProbe.getClass().getMethod("load", InputStream.class);
            Object loaded = loadMethod.invoke(yamlClassProbe, in);
            return flatten((Map<String, Object>) loaded, "");
        } catch (IOException e) {
            throw new InvalidConfigurationException("Failed to read config file: " + path, e);
        } catch (ReflectiveOperationException e) {
            throw new InvalidConfigurationException("Failed to parse YAML config file: " + path, e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> flatten(Map<String, Object> nested, String prefix) {
        Map<String, Object> flat = new java.util.HashMap<>();
        if (nested == null) {
            return flat;
        }
        for (Map.Entry<String, Object> entry : nested.entrySet()) {
            String key = prefix.isEmpty() ? entry.getKey() : prefix + "." + entry.getKey();
            if (entry.getValue() instanceof Map) {
                flat.putAll(flatten((Map<String, Object>) entry.getValue(), key));
            } else {
                flat.put(key, entry.getValue());
            }
        }
        return flat;
    }

    private static VerifierM2MClientConfig toConfig(Map<String, Object> raw, Path source) {
        String verifierUrl = requireString(raw, "verifier.url", source);
        String privateKeyJwk =
                resolveInlineOrPath(
                        raw,
                        "verifier.client.private-key-jwk",
                        "verifier.client.private-key-jwk-path",
                        source);
        String credentialJwt =
                resolveInlineOrPath(
                        raw,
                        "verifier.client.credential-jwt",
                        "verifier.client.credential-jwt-path",
                        source);
        return new VerifierM2MClientConfig(verifierUrl, privateKeyJwk, credentialJwt);
    }

    private static String resolveInlineOrPath(
            Map<String, Object> raw, String inlineKey, String pathKey, Path source) {
        Object inline = raw.get(inlineKey);
        Object filePath = raw.get(pathKey);
        if (inline != null && filePath != null) {
            throw new InvalidConfigurationException(
                    "Config file "
                            + source
                            + " sets both '"
                            + inlineKey
                            + "' and '"
                            + pathKey
                            + "' — set only one");
        }
        if (inline != null) {
            return String.valueOf(inline);
        }
        if (filePath != null) {
            Path resolved = resolveWithinConfigDirectory(source, String.valueOf(filePath), pathKey);
            try {
                return Files.readString(resolved);
            } catch (IOException e) {
                throw new InvalidConfigurationException(
                        "Failed to read file referenced by '" + pathKey + "': " + resolved, e);
            }
        }
        throw new InvalidConfigurationException(
                "Config file " + source + " is missing '" + inlineKey + "' or '" + pathKey + "'");
    }

    /**
     * Resolves a {@code *-path} config value relative to the config file's own directory,
     * rejecting anything that escapes it (absolute paths, {@code ../} traversal). A config
     * file that could reference an arbitrary filesystem path would let anyone able to write
     * that config file read files they otherwise couldn't — e.g. a sibling service's private
     * key — and have this SDK transmit them to the configured Verifier.
     */
    private static Path resolveWithinConfigDirectory(Path source, String rawPath, String pathKey) {
        Path configDir = source.toAbsolutePath().normalize().getParent();
        Path candidate = Path.of(rawPath);
        if (candidate.isAbsolute()) {
            throw new InvalidConfigurationException(
                    "'" + pathKey + "' must be a relative path, not absolute: " + rawPath);
        }
        Path resolved = configDir.resolve(candidate).normalize();
        if (!resolved.startsWith(configDir)) {
            throw new InvalidConfigurationException(
                    "'" + pathKey + "' must not escape the config file's directory: " + rawPath);
        }
        return resolved;
    }

    private static String requireString(Map<String, Object> raw, String key, Path source) {
        Object value = raw.get(key);
        if (value == null || String.valueOf(value).isBlank()) {
            throw new InvalidConfigurationException(
                    "Config file " + source + " is missing required key: " + key);
        }
        return String.valueOf(value);
    }
}
