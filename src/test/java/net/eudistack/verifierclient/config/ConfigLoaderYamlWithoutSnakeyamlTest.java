package net.eudistack.verifierclient.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Verifies that loading a {@code .yaml} file fails gracefully — a clear
 * {@code InvalidConfigurationException}, no stack trace leaking file contents — when
 * SnakeYAML genuinely isn't on the classpath, rather than reasoning about the reflective
 * lookup by inspection alone.
 *
 * <p>Runs {@link ConfigLoader} under a child classloader that refuses to load
 * {@code org.yaml.snakeyaml.*}, so {@code Class.forName("org.yaml.snakeyaml.Yaml")} genuinely
 * throws {@link ClassNotFoundException} — the same failure mode a consumer who didn't add the
 * optional SnakeYAML dependency would hit.
 */
class ConfigLoaderYamlWithoutSnakeyamlTest {

    @Test
    void loadingYamlWithoutSnakeyamlFailsWithInvalidConfigurationExceptionNotAStackTrace(
            @TempDir Path tempDir) throws Exception {
        Path yamlFile = tempDir.resolve("verifier-client.yaml");
        Files.writeString(
                yamlFile,
                """
                verifier:
                  url: https://verifier.example.org
                  private-key-jwk: '{"kty":"EC"}'
                  credential-jwt: header.payload.signature
                """);

        ClassLoader withoutSnakeyaml = classLoaderHidingSnakeyaml();
        Class<?> configLoaderInIsolatedLoader =
                Class.forName(ConfigLoader.class.getName(), true, withoutSnakeyaml);
        Method load = configLoaderInIsolatedLoader.getMethod("load", Path.class);

        assertThat(configLoaderInIsolatedLoader.getClassLoader()).isEqualTo(withoutSnakeyaml);

        try {
            load.invoke(null, yamlFile);
            throw new AssertionError("Expected InvalidConfigurationException to be thrown");
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            assertThat(cause.getClass().getName())
                    .isEqualTo("net.eudistack.verifierclient.exception.InvalidConfigurationException");
            assertThat(cause).hasMessageContaining("snakeyaml");
            assertThat(cause.getCause()).isInstanceOf(ClassNotFoundException.class);
        }
    }

    private static ClassLoader classLoaderHidingSnakeyaml() {
        String[] classpathEntries = System.getProperty("java.class.path").split(java.io.File.pathSeparator);
        URL[] urls =
                java.util.Arrays.stream(classpathEntries)
                        .map(entry -> Path.of(entry).toUri())
                        .map(
                                uri -> {
                                    try {
                                        return uri.toURL();
                                    } catch (java.net.MalformedURLException e) {
                                        throw new IllegalStateException(e);
                                    }
                                })
                        .toArray(URL[]::new);
        return new URLClassLoader(urls, ClassLoader.getPlatformClassLoader()) {
            @Override
            public Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (name.startsWith("org.yaml.snakeyaml.")) {
                    throw new ClassNotFoundException(name);
                }
                return super.loadClass(name, resolve);
            }

            @Override
            protected Class<?> findClass(String name) throws ClassNotFoundException {
                if (name.startsWith("org.yaml.snakeyaml.")) {
                    throw new ClassNotFoundException(name);
                }
                return super.findClass(name);
            }
        };
    }
}
