package com.olus.nnmrls.authorizationserver.controller;

import com.olus.nnmrls.authorizationserver.domain.Role;
import com.olus.nnmrls.authorizationserver.domain.User;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import java.util.Set;

import static com.olus.nnmrls.authorizationserver.controller.AuthApi.BEARER;
import static com.olus.nnmrls.authorizationserver.controller.AuthApi.EXPIRY;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthApiTest {
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtEncoder jwtEncoder;
    private AuthApi authApi;

    @BeforeEach
    void beforeEach() {
        reset(authenticationManager, jwtEncoder);
        authApi = new AuthApi(authenticationManager, jwtEncoder);
    }

    @Test
    void testHappyPath() {

        // Setup
        var client = "client";
        var secret = "secret";
        var encoded = Base64.encodeBase64((client + ":" + secret).getBytes());
        var authorization = "Basic " + new String(encoded);

        var user = new User();
        user.setId("1");
        user.setUsername("client");
        user.setPassword("password");
        var role = new Role();
        role.setAuthority("USER");
        user.setAuthorities(Set.of(role));
        var authentication = new UsernamePasswordAuthenticationToken(user, "secret");

        when(authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(client, secret))).thenReturn(authentication);
        var jwt = mock(Jwt.class);
        when(jwt.getTokenValue()).thenReturn("token value");
        when(jwtEncoder.encode(any())).thenReturn(jwt);

        // Execute
        var response = authApi.login(authorization, "client_credentials");
        assertEquals(HttpStatus.OK, response.getStatusCode());
        var tokenResponse = response.getBody();
        assertNotNull(tokenResponse);
        assertEquals("token value", tokenResponse.getAccessToken());
        assertEquals(BEARER, tokenResponse.getTokenType());
        assertEquals(EXPIRY, tokenResponse.getExpiresIn());
    }
}
