package com.olus.nnmrls.authorizationserver.controller;

import com.olus.nnmrls.authorizationserver.domain.User;
import com.olus.nnmrls.authorizationserver.vo.TokenResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

import static java.lang.String.format;
import static java.util.stream.Collectors.joining;

/**
 * Api to get access token
 *
 * @author Oleksii Usatov
 */
@RestController
@RequestMapping(path = "/api/public")
@RequiredArgsConstructor
public class AuthApi {
    public static final String BEARER = "Bearer";
    private static final Long EXPIRY = 36000L;
    public static final String BASIC_ = "Basic ";
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;

    @PostMapping("/token")
    public ResponseEntity<TokenResponse> login(@RequestHeader("Authorization") @Valid String authorization) {
        try {
            if (!StringUtils.hasText(authorization) || !authorization.startsWith(BASIC_)) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }
            var credentials = authorization.substring(BASIC_.length());
            var clientCredentials = new String(Base64.decodeBase64(credentials));
            var clientId = clientCredentials.substring(0, clientCredentials.indexOf(":"));
            var clientSecret = clientCredentials.substring(clientCredentials.indexOf(":") + 1);
            var authentication =
                    authenticationManager.authenticate(
                            new UsernamePasswordAuthenticationToken(clientId, clientSecret));
            var user = (User) authentication.getPrincipal();
            var now = Instant.now();
            var scope = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(joining(" "));
            var claims =
                    JwtClaimsSet.builder()
                            .issuer("nnmrls-auth.io")
                            .issuedAt(now)
                            .expiresAt(now.plusSeconds(EXPIRY))
                            .subject(format("%s,%s", user.getId(), user.getUsername()))
                            .claim("roles", scope)
                            .build();
            var token = this.jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
            return ResponseEntity.ok()
                    .body(TokenResponse.builder()
                            .tokenType(BEARER)
                            .accessToken(token)
                            .expiresIn(EXPIRY)
                            .build());
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }
}