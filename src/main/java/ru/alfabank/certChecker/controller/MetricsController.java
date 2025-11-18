package ru.alfabank.certChecker.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

@RestController
public class MetricsController {

    @Value("${certificates.search.path:/etc/certificates}")
    private String certificatesSearchPath;

    private Path getSearchPathFromConfig() {
        return Paths.get(certificatesSearchPath);
    }


    @GetMapping("/metrics")
    public String getMetrics() {
        // Инкрементируем счетчик при каждом запросе
        // Получаем текущее время в Unix timestamp
        long currentTime = Instant.now().getEpochSecond();

        // Формируем ответ в формате Prometheus
        StringBuilder metrics = new StringBuilder();

       // метрика файлоы jks и pem

        metrics.append("# HELP certificate_files_count Number of JKS and PEM files found\n");
        metrics.append("# TYPE certificate_files_count gauge\n");

        try {
            Path searchPath = getSearchPathFromConfig();
            long jksCount = countFilesByExtension(searchPath, "jks");
            long pemCount = countFilesByExtension(searchPath, "pem");

            metrics.append("certificate_files_count{type=\"jks\", jks_count=\"").append(jksCount).append("\" hostname=\"").append(getHostname()).append("\" }").append("\n");

            metrics.append("certificate_files_count{type=\"pem\", pem_count=\"").append(pemCount).append("\" hostname=\"").append(getHostname()).append("\" }").append("\n");
        } catch (Exception e) {
            // В случае ошибки возвращаем -1 для обеих метрик
            metrics.append("certificate_files_count{type=\"jks\"} -1\n");
            metrics.append("certificate_files_count{type=\"pem\"} -1\n");
        }

        // Добавляем метрики для сертификатов из PEM файлов
        metrics.append("\n# HELP certificate_info Information about certificates in PEM files\n");
        metrics.append("# TYPE certificate_info gauge\n");

        try {
            Path searchPath = getSearchPathFromConfig();
            CertificateExtractor extractor = new CertificateExtractor();

            // Ищем все PEM файлы в папке и подпапках
            List<Path> pemFiles = findFilesByExtension(searchPath, "pem");

            for (Path pemFile : pemFiles) {
                List<CertificateExtractor.CertificateInfo> certificates =
                        extractor.extractCertificatesFromPem(pemFile);

                for (CertificateExtractor.CertificateInfo cert : certificates) {
                    metrics.append(String.format(
                            "certificate_info{file=\"%s\", cert_name=\"%s\", serial=\"%s\", valid=\"%s\"} %d\n",
                            pemFile,
//                            escapeLabelValue(cert.getFileName()),
                            escapeLabelValue(cert.getCertificateName()),
                            escapeLabelValue(cert.getSerialNumber()),
                            cert.isValid(),
                            cert.getDaysUntilExpiration()
                    ));
                }
            }

            // Если PEM файлов не найдено, добавляем метрику с 0
            if (pemFiles.isEmpty()) {
                metrics.append("certificate_info{file=\"none\", alias=\"none\", serial=\"none\", valid=\"false\"} 0\n");
            }
        } catch (Exception e) {
            metrics.append("certificate_info{file=\"error\", alias=\"error\", serial=\"error\", valid=\"false\"} -1\n");
        }


        // Добавляем метрики для сертификатов из JKS файлов

        try {
            Path searchPath = getSearchPathFromConfig();
            CertificateExtractorJKS extractor = new CertificateExtractorJKS();

            // Ищем все JKS файлы в папке и подпапках
            List<Path> jksFiles = findFilesByExtension(searchPath, "jks");
            jksFiles.forEach(System.out::println);

            for (Path jksFile : jksFiles){

                System.out.println("обрабатываю файл "+jksFile);
                List<CertificateExtractorJKS.CertificateInfo> certificates =
                        extractor.extractCertificatesFromJks(jksFile);


                for (CertificateExtractorJKS.CertificateInfo cert : certificates) {
                    System.out.println("перечень сертификатов" + cert.getCertificateName());

                    metrics.append(String.format(
                            "certificate_info{file=\"%s\", alias=\"%s\", serial=\"%s\", valid=\"%s\"} %d\n",
                            jksFile,
                            escapeLabelValue(cert.getCertificateName()),
                            escapeLabelValue(cert.getSerialNumber()),
                            cert.isValid(),
                            cert.getDaysUntilExpiration()
                    ));
                }
            }

            if (jksFiles.isEmpty()) {
                metrics.append("certificate_info{file=\"none\", alias=\"none\", serial=\"none\", valid=\"false\"} 0\n");
            }

        } catch (Exception e){
            metrics.append("certificate_info{file=\"error\", alias=\"error\", serial=\"error\", valid=\"false\"} -1\n");
        }


        // Обязательно добавляем # EOF в конце
        metrics.append("# EOF\n");

        return metrics.toString();
    }

    private String getHostname() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return "unknown-host";
        }
    }

    private long countFilesByExtension(Path directory, String extension) throws IOException {
        if (!Files.exists(directory) || !Files.isDirectory(directory)) {
            return 0;
        }

        try (Stream<Path> stream = Files.walk(directory)) {
            return stream
                    .filter(Files::isRegularFile)
                    .filter(path -> {
                        String fileName = path.getFileName().toString().toLowerCase();
                        return fileName.endsWith("." + extension.toLowerCase());
                    })
                    .count();
        }
    }

    private List<Path> findFilesByExtension(Path searchPath, String extension) throws IOException {
        List<Path> files = new ArrayList<>();
        Files.walk(searchPath)
                .filter(path -> {
                    // Проверяем что это файл (не директория) и расширение совпадает
                    String fileName = path.getFileName().toString().toLowerCase();
                    return Files.isRegularFile(path) && fileName.endsWith("." + extension.toLowerCase());
                })
                .forEach(files::add);
        return files;
    }

    /**
     * Вспомогательный метод для экранирования значений меток Prometheus
     */
    private String escapeLabelValue(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }


    private long getUptime() {
        return System.currentTimeMillis() / 1000;
    }
}