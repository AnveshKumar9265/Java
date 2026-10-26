package com.corebanking.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

@Service
public class AutomatedAccountSummaryExportService {

    private static final Logger log = LoggerFactory.getLogger(AutomatedAccountSummaryExportService.class);
    private final JdbcTemplate jdbcTemplate;

    @Value("${file.export.target-path}")
    private String targetPath;

    public AutomatedAccountSummaryExportService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    // Runs automatically every day at midnight (Change to "0 * * * * ?" for testing every minute)
    @Scheduled(cron = "0 0 0 * * ?")
    public void executeAutomatedExport() {
        log.info("Starting automated account summary file export to remote path...");
        try {
            // 1. Fetch live data from the view
            String sql = "SELECT * FROM view_accounts_summary";
            List<Map<String, Object>> rows = jdbcTemplate.queryForList(sql);

            if (rows.isEmpty()) {
                log.warn("No records found in view_accounts_summary. Skipping file generation.");
                return;
            }

            // 2. Format CSV Data
            StringBuilder csvBuilder = new StringBuilder();
            var headers = rows.get(0).keySet();
            csvBuilder.append(String.join(",", headers)).append("\n");

            for (Map<String, Object> row : rows) {
                StringBuilder line = new StringBuilder();
                for (String header : headers) {
                    Object val = row.get(header);
                    line.append(val != null ? "\"" + val.toString().replace("\"", "\"\"") + "\"" : "").append(",");
                }
                line.deleteCharAt(line.length() - 1);
                csvBuilder.append(line).append("\n");
            }

            // 3. Generate Timestamped Filename
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
            String fileName = "account_summary_" + timestamp + ".csv";

            // 4. Use java.io.File to safely handle remote UNC paths / IP shares
            File targetDirectory = new File(targetPath);
            if (!targetDirectory.exists()) {
                boolean created = targetDirectory.mkdirs();
                if (!created) {
                    log.error("Failed to create target remote directory: {}", targetPath);
                    return;
                }
            }

            File outputFile = new File(targetDirectory, fileName);
            Files.write(outputFile.toPath(), csvBuilder.toString().getBytes(StandardCharsets.UTF_8));

            log.info("Successfully exported account summary CSV to remote path: {}", outputFile.getAbsolutePath());

        } catch (Exception e) {
            log.error("CRITICAL: Automated remote file export failed due to error: {}", e.getMessage(), e);
        }
    }
}