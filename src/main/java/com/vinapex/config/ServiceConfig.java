package com.vinapex.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Component
@Configuration
public class ServiceConfig {
    //@Value("${signing.key}")
    private String jwtSigningKey="345345fsdfsf5345";

    public String getJwtSigningKey() {
        return jwtSigningKey;
    }

}