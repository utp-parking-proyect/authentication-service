package com.utp.authentication.config;

import com.utp.authentication.service.JwtService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class AppConfig {

  private static final String CORE_URL = System.getenv("CORE_URL");

  @Bean
  WebClient.Builder webClient(ObjectProvider<JwtService> jwtServiceProvider) {
    return WebClient.builder()
        .baseUrl(CORE_URL)
        .filter(serviceTokenFilter(jwtServiceProvider));
  }

  private ExchangeFilterFunction serviceTokenFilter(ObjectProvider<JwtService> jwtServiceProvider) {
    return (request, next) -> next.exchange(ClientRequest.from(request)
        .headers(headers -> headers.setBearerAuth(jwtServiceProvider.getObject()
            .generateServiceToken()))
        .build());
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}
