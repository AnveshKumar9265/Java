package com.corebanking.service;

import com.corebanking.dto.OnboardCustomerRequest;
import com.corebanking.dto.TransferRequest;
import com.corebanking.repository.CoreBankingRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Service
public class CoreBankingService {

    private final CoreBankingRepository repository;

    public CoreBankingService(CoreBankingRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public Map<String, Object> registerCustomerAndOpenAccount(OnboardCustomerRequest request) {
        return repository.onboardCustomerAndAccount(request);
    }

    @Transactional
    public Map<String, Object> transferFunds(TransferRequest request) {
        return repository.executeTransfer(request);
    }

    public Map<String, Object> getAccountSummary(String accountNumber) {
        Map<String, Object> summary = repository.getAccountSummary(accountNumber);
        if (summary == null) {
            throw new RuntimeException("Account number " + accountNumber + " not found.");
        }
        return summary;
    }

    public Map<String, Object> getTransactionStatus(String utrNumber) {
        Map<String, Object> status = repository.getTransactionStatusByUtr(utrNumber);
        if (status == null) {
            throw new RuntimeException("Transaction with UTR " + utrNumber + " not found.");
        }
        return status;
    }

    public List<Map<String, Object>> getPassbookStatement(String accountNumber) {
        return repository.getAccountStatement(accountNumber, 50);
    }
}