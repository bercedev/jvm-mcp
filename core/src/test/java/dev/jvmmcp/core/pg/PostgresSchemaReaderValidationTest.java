package dev.jvmmcp.core.pg;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PostgresSchemaReaderValidationTest {

    @ParameterizedTest
    @ValueSource(strings = {
        "jdbc:postgresql://localhost:5432/mydb",
        "jdbc:postgresql://127.0.0.1:5432/testdb",
        "jdbc:postgresql://[::1]:5432/ipv6db"
    })
    @DisplayName("Valid loopback JDBC URLs should pass validation")
    void shouldAcceptValidLoopbackUrls(String url) {
        assertThatCode(() -> PostgresSchemaReader.validateJdbcUrl(url))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("SSRF Bypass: Embedded userinfo in authority must be rejected")
    void shouldRejectUserinfoBypass() {
        String bypassUrl = "jdbc:postgresql://localhost:secret@attacker-db.com:5432/evil_db";
        assertThatThrownBy(() -> PostgresSchemaReader.validateJdbcUrl(bypassUrl))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Embedded userinfo");
    }

    @Test
    @DisplayName("SSRF Bypass: Multi-host connection syntax must be rejected")
    void shouldRejectMultiHostBypass() {
        String multiHostUrl = "jdbc:postgresql://localhost:5432,internal-database.corp:5432/db?targetServerType=secondary";
        assertThatThrownBy(() -> PostgresSchemaReader.validateJdbcUrl(multiHostUrl))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Multi-host");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "jdbc:postgresql://169.254.169.254/latest/meta-data",
        "jdbc:postgresql://google.com:5432/db",
        "jdbc:postgresql://10.0.0.1:5432/internal",
        "jdbc:postgresql://192.168.1.50:5432/lan"
    })
    @DisplayName("Non-loopback hosts must be rejected by SSRF protection")
    void shouldRejectNonLoopbackHosts(String url) {
        assertThatThrownBy(() -> PostgresSchemaReader.validateJdbcUrl(url))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("SSRF Protection");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "jdbc:postgresql://localhost:5432/db?socketFactory=org.newsclub.net.unix.AFUNIXSocketFactory$FactoryArg",
        "jdbc:postgresql://localhost:5432/db?sslfactory=org.example.EvilFactory",
        "jdbc:postgresql://localhost:5432/db?sslrootcert=/etc/passwd",
        "jdbc:postgresql://localhost:5432/db?options=-c%20statement_timeout=1",
        "jdbc:postgresql://localhost:5432/db?sslmode=disable"
    })
    @DisplayName("Dangerous connection property parameters must be rejected")
    void shouldRejectDangerousParameters(String url) {
        assertThatThrownBy(() -> PostgresSchemaReader.validateJdbcUrl(url))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Dangerous JDBC connection parameter");
    }

    @Test
    @DisplayName("validateSchemaName accepts valid SQL identifiers and defaults blank/null to public")
    void shouldValidateValidSchemaNames() {
        org.assertj.core.api.Assertions.assertThat(PostgresSchemaReader.validateSchemaName(null)).isEqualTo("public");
        org.assertj.core.api.Assertions.assertThat(PostgresSchemaReader.validateSchemaName("")).isEqualTo("public");
        org.assertj.core.api.Assertions.assertThat(PostgresSchemaReader.validateSchemaName("   ")).isEqualTo("public");
        org.assertj.core.api.Assertions.assertThat(PostgresSchemaReader.validateSchemaName("public")).isEqualTo("public");
        org.assertj.core.api.Assertions.assertThat(PostgresSchemaReader.validateSchemaName("my_schema_2026")).isEqualTo("my_schema_2026");
    }

    @Test
    @DisplayName("validateSchemaName folds an unquoted schema name to lowercase, as PostgreSQL does")
    void shouldFoldSchemaNamesToLowercase() {
        org.assertj.core.api.Assertions.assertThat(PostgresSchemaReader.validateSchemaName("Public")).isEqualTo("public");
        org.assertj.core.api.Assertions.assertThat(PostgresSchemaReader.validateSchemaName("MY_SCHEMA")).isEqualTo("my_schema");
        org.assertj.core.api.Assertions.assertThat(PostgresSchemaReader.validateSchemaName("  Sales  ")).isEqualTo("sales");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "public; DROP TABLE users;--",
        "schema' OR '1'='1",
        "schema-with-dashes",
        "123startsWithNumber",
        "schema$name",
        "schema name with spaces",
        "a_very_long_schema_name_that_exceeds_sixty_three_characters_in_total_length_which_is_invalid"
    })
    @DisplayName("validateSchemaName rejects malicious, invalid, or overly long SQL identifiers")
    void shouldRejectInvalidSchemaNames(String invalidSchema) {
        assertThatThrownBy(() -> PostgresSchemaReader.validateSchemaName(invalidSchema))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Invalid schema name");
    }
}
