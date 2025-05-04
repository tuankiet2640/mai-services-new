package com.maiservices.maiservices.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtService {
    private static final Logger log = LoggerFactory.getLogger(JwtService.class);

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private long jwtExpiration;

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshExpiration;

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        var roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        claims.put("roles", roles);
        return generateToken(claims, userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        log.info("Generating token for user: {}", userDetails.getUsername());
        log.debug("Extra claims included: {}", extraClaims.keySet());
        var roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
        extraClaims.put("roles", roles);
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(Map<String, Object> extraClaims, UserDetails userDetails, long expiration) {
        return Jwts.builder()
                .claims(extraClaims)
                .subject(userDetails.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public Instant extractExpirationAsInstant(String token) {
        Date expirationDate = extractExpiration(token);
        return expirationDate.toInstant();
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .keyLocator(map -> getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Key getSignInKey() {
        try {
            log.debug("Decoding JWT secret (Hex): {}", jwtSecret);
            byte[] keyBytes = Hex.decodeHex(jwtSecret);
            log.debug("Decoded key bytes length: {}", keyBytes.length);
            if (keyBytes.length < 32) {
                log.error("Provided JWT secret results in a key length ({}) shorter than required for HS256 (32 bytes).", keyBytes.length);
                throw new IllegalArgumentException("JWT secret key is too short for HS256");
            }
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (DecoderException e) {
            log.error("Failed to decode Hex JWT secret: {}", jwtSecret, e);
            throw new RuntimeException("Invalid JWT secret configuration (not valid Hex)", e);
        } catch (IllegalArgumentException e) {
            log.error("Failed to create HMAC SHA key from decoded secret bytes.", e);
            throw new RuntimeException("Invalid JWT secret configuration (cannot create key)", e);
        }
    }
}
