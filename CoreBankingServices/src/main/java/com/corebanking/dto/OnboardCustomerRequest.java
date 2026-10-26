package com.corebanking.dto;

import jakarta.validation.constraints.*;
import lombok.Data;
import java.math.BigDecimal;
import java.time.LocalDate;

@Data
public class OnboardCustomerRequest {
    @NotBlank(message = "First name is required")
    private String firstName;

    private String middleName;

    @NotBlank(message = "Last name is required")
    private String lastName;

    @NotNull(message = "Date of birth is required")
    private LocalDate dob;

    @NotBlank(message = "Gender is required")
    private String gender; // MALE, FEMALE, OTHER

    private String maritalStatus;

    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank(message = "Phone number is required")
    private String phone;

    @Pattern(regexp = "^[A-Z]{5}[0-9]{4}[A-Z]{1}$", message = "Invalid PAN number format")
    private String panNumber;

    @Pattern(regexp = "^[0-9]{4}$", message = "Aadhaar last 4 digits must be exactly 4 numbers")
    private String aadhaarLast4;

    @NotBlank(message = "Occupation is required")
    private String occupation;

    @NotNull(message = "Declared annual income is required")
    @DecimalMin(value = "0.0", inclusive = true, message = "Income cannot be negative")
    private BigDecimal declaredAnnualIncome;

    @NotBlank(message = "Address Line 1 is required")
    private String addressLine1;

    private String addressLine2;

    @NotBlank(message = "City is required")
    private String city;

    @NotBlank(message = "State is required")
    private String state;

    private String country = "India";

    @Pattern(regexp = "^[0-9]{6}$", message = "Pincode must be a 6-digit number")
    private String pincode;

    private String accountType = "SAVINGS";

    @NotNull(message = "Initial deposit is required")
    @DecimalMin(value = "0.0", inclusive = true, message = "Initial deposit cannot be negative")
    private BigDecimal initialDeposit;

    private String nomineeName;
    private String nomineeRelation;
    private BigDecimal averageSpends;
    private String deviceId;
}