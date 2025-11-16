package ru.alfabank.certChecker.controller;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainPageController {

       @GetMapping("/")
    public String home() {
           return "<html>" +
                   "<body>" +
                   "<h1>Welcome to Cert Checker Application!</h1>" +
                   "<p>Visit <a href=\"/metrics\">metrics</a> for Prometheus metrics</p>" +
                   "</body>" +
                   "</html>";
    }
}