package com.corebanking.dto;

import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import java.math.BigDecimal;

@Data
public class TransferRequest {
    @NotBlank(message = "Idempotency key is required to prevent double-charging")
    private String idempotencyKey;

    @NotBlank(message = "Sender account number is required")
    @Pattern(regexp = "^\\d{12}$", message = "Account number must be exactly 12 digits")
    private String debitAccountNumber;

    @NotBlank(message = "Receiver account number is required")
    @Pattern(regexp = "^\\d{12}$", message = "Account number must be exactly 12 digits")
    private String creditAccountNumber;

    @NotNull(message = "Transfer amount is required")
    @DecimalMin(value = "1.0000", message = "Transfer amount must be greater than zero")
    private BigDecimal amount;

    private String paymentMode = "IMPS"; // UPI, IMPS, NEFT, RTGS, INTERNAL_TRANSFER
    private String referenceNote;
    private String clientIp = "127.0.0.1";
}