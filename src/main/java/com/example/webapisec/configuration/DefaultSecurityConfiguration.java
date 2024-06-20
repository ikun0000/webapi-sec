package com.example.webapisec.configuration;

import com.example.webapisec.utils.RSAKeyProperties;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.util.StandardCharset;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class DefaultSecurityConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(DefaultSecurityConfiguration.class);
    private final RSAKeyProperties keys;

    @Autowired
    public DefaultSecurityConfiguration(RSAKeyProperties keys) {
        this.keys = keys;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService) {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        return new ProviderManager(daoAuthenticationProvider);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers("/api/**").permitAll()
                            .requestMatchers("/auth/**").permitAll()
                            .requestMatchers("/user/**").hasAnyAuthority("USER", "ADMIN")
                            .requestMatchers("/admin/**").hasAuthority("ADMIN");
                });

        http.oauth2ResourceServer(oauth2 -> {
            oauth2.jwt(jwt -> {
                jwt.jwtAuthenticationConverter(jwtAuthenticationConverter());
            });

            // 未认证
            oauth2.authenticationEntryPoint((request, response, authException) -> {
                // oauth2 认证失败导致的，还有一种可能是非oauth2认证失败导致的，比如没有传递token，但是访问受权限保护的方法
                if (authException instanceof OAuth2AuthenticationException oAuth2AuthenticationException) {
                    OAuth2Error error = oAuth2AuthenticationException.getError();
                    logger.warn("Authentication fail, Exception type: [{}],异常:[{}]",
                            authException.getClass().getName(), error);
                }

                response.setCharacterEncoding(StandardCharset.UTF_8.name());
                response.setContentType(MediaType.APPLICATION_JSON.toString());
                response.getWriter().write("""
                        {
                            "code": -1,
                            "msg": "该接口需要认证授权"
                        }
                        """);
            });

            // 未授权
            oauth2.accessDeniedHandler((request, response, accessDeniedException) -> {
                response.setCharacterEncoding(StandardCharset.UTF_8.name());
                response.setContentType(MediaType.APPLICATION_JSON.toString());
                response.getWriter().write("""
                        {
                            "code": -2,
                            "msg": "您没有该接口权限"
                        }
                        """);
            });
        });

        http.sessionManagement(session -> {
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        });


        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withPublicKey(keys.getRsaPublicKey()).build();
    }

    @Bean
    public JwtEncoder jwtEncoder() {
        JWK jwk = new RSAKey.Builder(keys.getRsaPublicKey())
                .privateKey(keys.getRsaPrivateKey())
                .build();
        JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(jwk));
        return new NimbusJwtEncoder(jwks);
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("permissions");
        jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }
}
