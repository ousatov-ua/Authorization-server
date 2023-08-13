package com.olus.nnmrls.authorizationserver.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.olus.nnmrls.authorizationserver.domain.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.IOException;
import java.io.InputStream;
import java.util.AbstractMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * User service. Currently, it just read users database from file
 *
 * @author Oleksii Usatov
 */
@Slf4j
public class UserService implements UserDetailsService {

    private final Map<String, User> users;

    public UserService() {
        try (final InputStream is = UserService.class.getResourceAsStream("/users.json");
        ) {
            var usersList = new ObjectMapper().readValue(is, new TypeReference<List<User>>() {
            });
            users = usersList.stream().map(user -> new AbstractMap.SimpleEntry<>(user.getUsername(), user))
                    .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            log.info("Users are loaded");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return users.get(username);
    }
}
