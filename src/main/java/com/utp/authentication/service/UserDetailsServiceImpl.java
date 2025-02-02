package com.utp.authentication.service;

import com.utp.authentication.model.dto.User;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RequiredArgsConstructor
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final WebClient.Builder webClient;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Map<String, String> params = new HashMap<>();
        params.put("username", username);
        try {
            User user = webClient.build()
                    .get()
                    .uri("/username/{username}", params)
                    .retrieve()
                    .bodyToMono(User.class)
                    .block();
            assert user != null;
            List<GrantedAuthority> roles = user.getRoles().stream()
                    .map(role -> (GrantedAuthority) role::getName)
                    .toList();
            return new org.springframework.security.core.userdetails.User(user.getUsername(),
                    user.getPassword(),
                    user.getActualRegistered(),
                    true,
                    true,
                    true,
                    roles);
        } catch (WebClientResponseException e) {
            throw new UsernameNotFoundException("User not found");
        }
    }
}
