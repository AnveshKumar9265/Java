package com.corebanking;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;


@EnableScheduling
@SpringBootApplication
public class CoreBankingServicesApplication {

    public static void main(String[] args) {
        SpringApplication.run(CoreBankingServicesApplication.class, args);
    }

}
