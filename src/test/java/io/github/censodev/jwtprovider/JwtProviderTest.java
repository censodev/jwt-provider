package io.github.censodev.jwtprovider;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.WeakKeyException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtProviderTest {
    static final String SECRET = "1234567890qwertyuiopasdfghjklzxcvbnm!@#$&*()";
    JwtProvider tokenProvider;
    CanAuth user;

    @BeforeEach
    void setUp() {
        tokenProvider = JwtProvider.builder()
                .secret(SECRET)
                .build();
        user = new UserTest(Arrays.asList("ROLE_ADMIN", "ROLE_CUSTOMER"), "admin");
    }

    @Test
    void generate() {
        assertDoesNotThrow(() -> tokenProvider.generate(user));
    }

    @Test
    void getCredentials() {
        String token = tokenProvider.generate(user);
        assertDoesNotThrow(() -> tokenProvider.getCredential(token, UserTest.class));
    }

    @Test
    void verifyTokenHappyCase() {
        String token = tokenProvider.generate(user);
        assertDoesNotThrow(() -> tokenProvider.verify(token));
    }

    @Test
    void verifyTokenExpectWeakKeyException() {
        String token = tokenProvider.generate(user);
        tokenProvider = tokenProvider.toBuilder()
                .secret("1234567890")
                .build();
        assertThrows(WeakKeyException.class, () -> tokenProvider.verify(token));
    }

    @Test
    void verifyTokenExpectMalformedJwtException() {
        String token = "1234567890";
        assertThrows(MalformedJwtException.class, () -> tokenProvider.verify(token));
    }

    @Test
    void verifyTokenExpectExpiredJwtException() {
        String token = tokenProvider.generate(user, 1);
        assertThrows(ExpiredJwtException.class, () -> tokenProvider.verify(token));
    }

    @Test
    void getHeader() {
        assertEquals("Authorization", tokenProvider.getHeader());
    }

    @Test
    void getPrefix() {
        assertEquals("Bearer ", tokenProvider.getPrefix());
    }

    @Test
    void getExpiration() {
        assertEquals(3_600_000, tokenProvider.getDefaultExpireInMillisecond());
    }

    @Test
    void getSecret() {
        assertEquals(SECRET, tokenProvider.getSecret());
    }

    @Test
    void getCredentialClaimKey() {
        assertEquals("credential", tokenProvider.getCredentialClaimKey());
    }

    @Test
    void getSignatureAlgorithm() {
        assertEquals(SignatureAlgorithm.HS256, tokenProvider.getSignatureAlgorithm());
    }

    @Test
    void getSubject() {
        String token = tokenProvider.generate(user);
        assertEquals(user.subject(), tokenProvider.getSubject(token));
    }
}