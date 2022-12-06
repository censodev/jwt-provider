package io.github.censodev.jwtprovider;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.jsonwebtoken.security.Keys;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Builder(toBuilder = true)
@Getter
public class JwtProvider {
    private static final String CREDENTIAL_CLAIM_KEY = "credentials";
    @NonNull
    private String secret;
    @Builder.Default
    private Integer defaultExpireInMs = 3_600_000;
    @Builder.Default
    private SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
    @Builder.Default
    private ObjectMapper jsonMapper = JsonMapper.builder()
            .findAndAddModules()
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .build();

    /**
     * Initiate token provider builder
     *
     * @param secret secret key for the token provider
     * @return token provider builder
     */
    public static JwtProviderBuilder secret(String secret) {
        return builder().secret(secret);
    }

    private static JwtProviderBuilder builder() {
        return new JwtProviderBuilder();
    }

    /**
     * Retrieve subject from the token
     *
     * @param token JWT
     * @return subject of JWT
     */
    public Object getSubject(String token) {
        return getClaims(token).getSubject();
    }

    /**
     * Retrieve credentials from the token
     *
     * @param token           JWT
     * @param credentialsType type of credentials
     * @return claim of JWT contains credentials
     */
    public <T extends CanAuth> T getCredential(String token, Class<T> credentialsType) {
        Map<?, ?> credInMap = getClaims(token).get(CREDENTIAL_CLAIM_KEY, Map.class);
        return jsonMapper.convertValue(credInMap, credentialsType);
    }

    /**
     * Verify the token
     *
     * @param token JWT
     * @throws JwtException exception will be thrown when verifying failed
     */
    public void verify(String token) throws JwtException {
        Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token);
    }

    /**
     * Generate JWT with credentials and default expire duration
     *
     * @param canAuth credentials will be embedded in the token
     * @return JWT
     */
    public <T extends CanAuth> String generate(T canAuth) {
        return generate(canAuth, defaultExpireInMs);
    }

    /**
     * Generate JWT with credentials and expire duration
     *
     * @param canAuth             credentials will be embedded in the token
     * @param expireInMillisecond expire duration of the token (ms)
     * @return JWT
     */
    public <T extends CanAuth> String generate(T canAuth, Integer expireInMillisecond) {
        Instant now = Instant.now();
        Instant expiredInstant = now.plusMillis(expireInMillisecond);
        return Jwts.builder()
                .serializeToJsonWith(new JacksonSerializer<>(jsonMapper))
                .setSubject(canAuth.subject().toString())
                .claim(CREDENTIAL_CLAIM_KEY, canAuth)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiredInstant))
                .signWith(getKey(), signatureAlgorithm)
                .compact();
    }

    private Key getKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    private Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .deserializeJsonWith(new JacksonDeserializer<>(jsonMapper))
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
