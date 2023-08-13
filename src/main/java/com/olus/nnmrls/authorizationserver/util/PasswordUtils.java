package com.olus.nnmrls.authorizationserver.util;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * Utils to encrypt passwords
 *
 * @author Oleksii Usatov
 */
public class PasswordUtils {

    private static final BCryptPasswordEncoder ENCODER = new BCryptPasswordEncoder();

    private PasswordUtils() {

        // empty
    }

    public static void encode() {
        System.out.println(ENCODER.encode("password"));
    }
}
