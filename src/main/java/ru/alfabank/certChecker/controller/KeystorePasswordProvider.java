package ru.alfabank.certChecker.controller;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix = "keystore")
public class KeystorePasswordProvider {

    private static List<String> passwords;

    // Геттер для Spring (не static)
    public List<String> getPasswords() {
        return passwords;
    }

    // Сеттер для Spring (не static)
    public void setPasswords(List<String> passwords) {
        KeystorePasswordProvider.passwords = passwords;
    }

    // Статический метод для получения всех паролей
    public static List<String> getPassword() {
        return passwords;
    }
}