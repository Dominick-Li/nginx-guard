package com.ljm.nginx.guard;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class GuardApplication {
    public static void main(String[] args) {
        SpringApplication.run(GuardApplication.class, args);
    }

}
