package ru.alfabank.certChecker.controller;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CertificateExtractor {

    /**
     * Класс для хранения информации о сертификате
     */
    public static class CertificateInfo {
        private String fileName;
        private String certificateName;
        private String serialNumber;
        private long daysUntilExpiration;
        private boolean isValid;

        public CertificateInfo(String fileName, String certificateName, String serialNumber,
                               long daysUntilExpiration, boolean isValid) {
            this.fileName = fileName;
            this.certificateName = certificateName;
            this.serialNumber = serialNumber;
            this.daysUntilExpiration = daysUntilExpiration;
            this.isValid = isValid;
        }

        // Getters
        public String getFileName() { return fileName; }
        public String getCertificateName() { return certificateName; }
        public String getSerialNumber() { return serialNumber; }
        public long getDaysUntilExpiration() { return daysUntilExpiration; }
        public boolean isValid() { return isValid; }
    }

    /**
     * Извлекает все сертификаты из PEM файла
     */
    public List<CertificateInfo> extractCertificatesFromPem(Path pemFilePath) {
        List<CertificateInfo> certificates = new ArrayList<>();

        try {
            String content = Files.readString(pemFilePath);
            List<String> certificateBlocks = extractCertificateBlocks(content);

            for (int i = 0; i < certificateBlocks.size(); i++) {
                try {
                    X509Certificate cert = parseCertificate(certificateBlocks.get(i));
                    CertificateInfo certInfo = createCertificateInfo(pemFilePath, cert, i);
                    certificates.add(certInfo);
                } catch (CertificateException e) {
                    // Создаем информацию о невалидном сертификате
                    CertificateInfo invalidCert = new CertificateInfo(
                            pemFilePath.getFileName().toString(),
                            "invalid_certificate_" + i,
                            "unknown",
                            -1,
                            false
                    );
                    certificates.add(invalidCert);
                }
            }

        } catch (IOException e) {
            // В случае ошибки чтения файла
            CertificateInfo errorCert = new CertificateInfo(
                    pemFilePath.getFileName().toString(),
                    "error_reading_file",
                    "unknown",
                    -1,
                    false
            );
            certificates.add(errorCert);
        }

        return certificates;
    }

    /**
     * Извлекает блоки сертификатов из PEM контента
     */
    private List<String> extractCertificateBlocks(String pemContent) {
        List<String> blocks = new ArrayList<>();
        Pattern pattern = Pattern.compile(
                "-+BEGIN CERTIFICATE-+([\\s\\S]*?)-+END CERTIFICATE-+",
                Pattern.CASE_INSENSITIVE
        );

        Matcher matcher = pattern.matcher(pemContent);
        while (matcher.find()) {
            blocks.add(matcher.group(0));
        }

        return blocks;
    }

    /**
     * Парсит PEM блок в X509Certificate
     */
    private X509Certificate parseCertificate(String pemBlock) throws CertificateException {
        try {
            // Удаляем заголовки и футеры, оставляем только base64
            String base64 = pemBlock
                    .replaceAll("-+BEGIN CERTIFICATE-+", "")
                    .replaceAll("-+END CERTIFICATE-+", "")
                    .replaceAll("\\s", "");

            byte[] certBytes = Base64.getDecoder().decode(base64);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(
                    new ByteArrayInputStream(certBytes)
            );

        } catch (IllegalArgumentException e) {
            throw new CertificateException("Invalid base64 encoding", e);
        }
    }

    /**
     * Создает объект CertificateInfo из X509Certificate
     */
    private CertificateInfo createCertificateInfo(Path filePath, X509Certificate cert, int index) {
        String fileName = filePath.getFileName().toString();
        String certName = getCertificateName(cert, index);
        String serialNumber = cert.getSerialNumber().toString(16); // hex representation
        long daysUntilExpiration = calculateDaysUntilExpiration(cert);
        boolean isValid = isCertificateValid(cert);

        return new CertificateInfo(fileName, certName, serialNumber, daysUntilExpiration, isValid);
    }

    /**
     * Получает имя сертификата (Common Name или Subject)
     */
    private String getCertificateName(X509Certificate cert, int index) {
        String subject = cert.getSubjectX500Principal().getName();

        // Пытаемся извлечь CN (Common Name)
        Pattern cnPattern = Pattern.compile("CN=([^,]+)");
        Matcher matcher = cnPattern.matcher(subject);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }

        // Если CN не найден, используем первую часть subject
        if (subject.contains(",")) {
            return subject.split(",")[0].trim();
        }

        return "certificate_" + index;
    }

    /**
     * Вычисляет количество дней до истечения срока действия сертификата
     */
    private long calculateDaysUntilExpiration(X509Certificate cert) {
        Date expirationDate = cert.getNotAfter();
        Date currentDate = new Date();

        long diff = expirationDate.getTime() - currentDate.getTime();
        return diff / (1000 * 60 * 60 * 24); // Convert milliseconds to days
    }

    /**
     * Проверяет валидность сертификата
     */
    private boolean isCertificateValid(X509Certificate cert) {
        try {
            cert.checkValidity();
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}