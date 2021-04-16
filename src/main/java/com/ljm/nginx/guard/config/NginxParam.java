package com.ljm.nginx.guard.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * @author Dominick Li
 * @CreateTime 2021/1/12 18:42
 * @description
 **/
@Configuration
@ConfigurationProperties(prefix = "nginx")
@Data
public class NginxParam {

    private String sbin;

    private String log;

    private String blackListIp;

    private String pingPort;

    private List<String> matcherList;

}
