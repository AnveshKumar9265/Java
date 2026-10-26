package com.corebanking.controller;

import com.corebanking.repository.CoreBankingRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/security")
public class SecurityController {

    private final CoreBankingRepository repository;

    public SecurityController(CoreBankingRepository repository) {
        this.repository = repository;
    }

    @PostMapping("/block-accounts")
    public ResponseEntity<Map<String, Object>> blockAccountsDueToAnomaly(@RequestBody Map<String, String> request) {
        String sender = request.get("senderAccountNumber");
        String receiver = request.get("receiverAccountNumber");
        String reason = request.get("reason");

        Map<String, Object> response = repository.blockAccounts(sender, receiver, reason);
        if (response != null && "SUCCESS".equals(response.get("status"))) {
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(500).body(Map.of("error", "Failed to block accounts"));
    }
}