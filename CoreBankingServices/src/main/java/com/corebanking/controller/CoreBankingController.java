package com.corebanking.controller;

import com.corebanking.dto.OnboardCustomerRequest;
import com.corebanking.dto.TransferRequest;
import com.corebanking.service.CoreBankingService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/banking")
public class CoreBankingController {

    private final CoreBankingService bankingService;

    public CoreBankingController(CoreBankingService bankingService) {
        this.bankingService = bankingService;
    }

    @PostMapping("/onboard-customer")
    public ResponseEntity<Map<String, Object>> onboardCustomer(@Valid @RequestBody OnboardCustomerRequest request) {
        return ResponseEntity.ok(bankingService.registerCustomerAndOpenAccount(request));
    }

    @PostMapping("/fund-transfer")
    public ResponseEntity<Map<String, Object>> transferFunds(@Valid @RequestBody TransferRequest request) {
        return ResponseEntity.ok(bankingService.transferFunds(request));
    }

    @GetMapping("/account-summary/{accountNumber}")
    public ResponseEntity<Map<String, Object>> getAccountSummary(@PathVariable String accountNumber) {
        return ResponseEntity.ok(bankingService.getAccountSummary(accountNumber));
    }

    @GetMapping("/get-transaction-status/{utrNumber}")
    public ResponseEntity<Map<String, Object>> getTransactionStatus(@PathVariable String utrNumber) {
        return ResponseEntity.ok(bankingService.getTransactionStatus(utrNumber));
    }

    @GetMapping("/get-mini-statement/{accountNumber}")
    public ResponseEntity<List<Map<String, Object>>> getAccountStatement(@PathVariable String accountNumber) {
        return ResponseEntity.ok(bankingService.getPassbookStatement(accountNumber));
    }
}