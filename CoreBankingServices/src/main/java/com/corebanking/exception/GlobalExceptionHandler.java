package com.corebanking.exception;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // Catch validation errors (e.g., invalid PAN format or missing fields)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        for (FieldError error : ex.getBindingResult().getFieldErrors()) {
            errors.put(error.getField(), error.getDefaultMessage());
        }

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.BAD_REQUEST.value());
        response.put("error", "Validation Failed");
        response.put("messages", errors);

        return ResponseEntity.badRequest().body(response);
    }

    // Catch PostgreSQL Unique Key violations (e.g. PAN or Email already registered)
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<Map<String, Object>> handleDatabaseExceptions(DataAccessException ex) {
        String rootMsg = ex.getMostSpecificCause().getMessage();
        String userFriendlyMessage = "A database error occurred.";

        if (rootMsg != null && rootMsg.contains("customers_pan_number_key")) {
            userFriendlyMessage = "A customer with this PAN number is already registered.";
        } else if (rootMsg != null && rootMsg.contains("customers_email_key")) {
            userFriendlyMessage = "This email address is already registered.";
        } else if (rootMsg != null && rootMsg.contains("customers_phone_key")) {
            userFriendlyMessage = "This phone number is already registered.";
        }

        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.CONFLICT.value());
        response.put("error", "Database Constraint Violation");
        response.put("message", userFriendlyMessage);
        response.put("details", rootMsg);

        return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
    }

    // Catch all other unexpected errors
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
        Map<String, Object> response = new HashMap<>();
        response.put("timestamp", LocalDateTime.now());
        response.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        response.put("error", "Internal Server Error");
        response.put("message", ex.getMessage());

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}