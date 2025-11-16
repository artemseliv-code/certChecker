package ru.alfabank.certChecker.controller;

import org.springframework.beans.factory.annotation.Value;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

public class CertificateExtractorJKS {

    @Value("${keystore-passwords:/etc/certificates}")
    private List<String> configPasswords;



    private List<String> keystorePasswords;

    public CertificateExtractorJKS() {
        this.keystorePasswords = loadKeystorePasswordsFromConfig();
    }

    public static class CertificateInfo {
        private String fileName;
        private String certificateName;
        private String serialNumber;
        private boolean isValid;
        private long daysUntilExpiration;

        public CertificateInfo(String fileName, String certificateName, String serialNumber,
                               boolean isValid, long daysUntilExpiration) {
            this.fileName = fileName;
            this.certificateName = certificateName;
            this.serialNumber = serialNumber;
            this.isValid = isValid;
            this.daysUntilExpiration = daysUntilExpiration;
        }

        // Getters
        public String getFileName() { return fileName; }
        public String getCertificateName() { return certificateName; }
        public String getSerialNumber() { return serialNumber; }
        public boolean isValid() { return isValid; }
        public long getDaysUntilExpiration() { return daysUntilExpiration; }
    }

    private List<String> loadKeystorePasswordsFromConfig() {
        List<String> passwords = new ArrayList<>();


        // Здесь должна быть логика загрузки паролей из конфигурации
        // Временная реализация с дефолтными паролями
        passwords.add("changeit");
        passwords.add("");
        passwords.forEach(System.out::println);
        return passwords;
    }

    public List<CertificateInfo> extractCertificatesFromJks(Path jksFile) {
        List<CertificateInfo> certificates = new ArrayList<>();
        System.out.println("обрабатываю файл " + jksFile);

        for (String password : keystorePasswords) {
            System.out.println("пароль " + password);

            try {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                try (FileInputStream fis = new FileInputStream(jksFile.toFile())) {

                    char[] passwordChars = (password == null || password.trim().isEmpty())
                            ? null
                            : password.toCharArray();

                    keyStore.load(fis, passwordChars);

                    Enumeration<String> aliases = keyStore.aliases();



                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        System.out.println("алиас кейстора " + alias);
                        Certificate cert = keyStore.getCertificate(alias);

                        if (cert instanceof X509Certificate) {
                            X509Certificate x509Cert = (X509Certificate) cert;
                            CertificateInfo certInfo = createCertificateInfo(
                                    jksFile, alias, x509Cert
                            );
                            certificates.add(certInfo);
                        }
                    }
                    // Если успешно загрузили ключевое хранилище, выходим из цикла
                    break;
                }
            } catch (IOException e) {
                // Неверный пароль или файл поврежден, пробуем следующий пароль
                continue;
            } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
                // Другие ошибки - логируем и продолжаем
                System.err.println("Error processing JKS file " + jksFile + ": " + e.getMessage());
                break;
            }
        }

        return certificates;
    }

    private CertificateInfo createCertificateInfo(Path jksFile, String alias, X509Certificate cert) {
        String fileName = jksFile.getFileName().toString();
        String certName = alias;
        String serialNumber = cert.getSerialNumber().toString(16); // hex representation

        Date now = new Date();
        boolean isValid = now.after(cert.getNotBefore()) && now.before(cert.getNotAfter());

        long daysUntilExpiration = calculateDaysUntilExpiration(cert.getNotAfter());

        return new CertificateInfo(fileName, certName, serialNumber, isValid, daysUntilExpiration);
    }

    private long calculateDaysUntilExpiration(Date expirationDate) {
        long diff = expirationDate.getTime() - new Date().getTime();
        return diff / (1000 * 60 * 60 * 24); // Convert milliseconds to days
    }

    // Метод для совместимости с существующим кодом (опечатка в названии метода)
    public List<CertificateInfo> extractCertificatesFromPem(Path jksFile) {
        return extractCertificatesFromJks(jksFile);
    }

    // Setters and getters
    public void setKeystorePasswords(List<String> keystorePasswords) {
        this.keystorePasswords = keystorePasswords;
    }

    public List<String> getKeystorePasswords() {
        return keystorePasswords;
    }
}