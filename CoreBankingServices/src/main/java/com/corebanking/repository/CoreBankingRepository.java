package com.corebanking.repository;

import com.corebanking.dto.TransferRequest;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import com.corebanking.dto.OnboardCustomerRequest;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Repository
public class CoreBankingRepository {

    private final NamedParameterJdbcTemplate jdbcTemplate;

    public CoreBankingRepository(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public Map<String, Object> onboardCustomerAndAccount(OnboardCustomerRequest req) {
        String sql = """
            SELECT * FROM onboard_customer_and_open_account(
                :firstName, :middleName, :lastName, :dob, 
                :gender::gender_type, :maritalStatus::marital_status_type, 
                :email, :phone, :panNumber, :aadhaarLast4, 
                :occupation::occupation_type, :declaredAnnualIncome, 
                :addressLine1, :addressLine2, :city, :state, :country, :pincode, 
                :accountType::account_type, :initialDeposit, :nomineeName, :nomineeRelation, :deviceId, :averageSpends
            )
        """;

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("firstName", req.getFirstName())
                .addValue("middleName", req.getMiddleName())
                .addValue("lastName", req.getLastName())
                .addValue("dob", req.getDob())
                .addValue("gender", req.getGender())
                .addValue("maritalStatus", req.getMaritalStatus() != null ? req.getMaritalStatus() : "SINGLE")
                .addValue("email", req.getEmail())
                .addValue("phone", req.getPhone())
                .addValue("panNumber", req.getPanNumber().toUpperCase().trim())
                .addValue("aadhaarLast4", req.getAadhaarLast4())
                .addValue("occupation", req.getOccupation())
                .addValue("declaredAnnualIncome", req.getDeclaredAnnualIncome())
                .addValue("addressLine1", req.getAddressLine1())
                .addValue("addressLine2", req.getAddressLine2())
                .addValue("city", req.getCity())
                .addValue("state", req.getState())
                .addValue("country", req.getCountry())
                .addValue("pincode", req.getPincode())
                .addValue("accountType", req.getAccountType())
                .addValue("initialDeposit", req.getInitialDeposit())
                .addValue("nomineeName", req.getNomineeName())
                .addValue("nomineeRelation", req.getNomineeRelation())
                .addValue("deviceId", req.getDeviceId())
                .addValue("averageSpends", req.getAverageSpends());

        return jdbcTemplate.query(sql, params, rs -> {
            if (rs.next()) {
                Map<String, Object> result = new HashMap<>();
                result.put("customerId", rs.getString("out_customer_id"));
                result.put("cifNumber", rs.getString("out_cif_number"));
                result.put("accountId", rs.getString("out_account_id"));
                result.put("accountNumber", rs.getString("out_account_number"));
                result.put("currentBalance", rs.getBigDecimal("out_current_balance"));
                result.put("message", rs.getString("out_message"));
                return result;
            }
            return null;
        });
    }

    public Map<String, Object> executeTransfer(TransferRequest req) {
        String sql = """
            SELECT * FROM transfer_funds_by_account_number(
                :idempotencyKey, :debitAcc, :creditAcc, :amount, 
                :paymentMode::payment_mode, :refNote, :clientIp
            )
        """;

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("idempotencyKey", req.getIdempotencyKey())
                .addValue("debitAcc", req.getDebitAccountNumber())
                .addValue("creditAcc", req.getCreditAccountNumber())
                .addValue("amount", req.getAmount())
                .addValue("paymentMode", req.getPaymentMode())
                .addValue("refNote", req.getReferenceNote())
                .addValue("clientIp", req.getClientIp());

        return jdbcTemplate.query(sql, params, rs -> {
            if (rs.next()) {
                Map<String, Object> result = new HashMap<>();
                result.put("paymentId", rs.getString("out_payment_id"));
                result.put("utrNumber", rs.getString("out_utr_number"));
                result.put("status", rs.getString("out_status"));
                result.put("senderClosingBalance", rs.getBigDecimal("out_debit_closing_balance"));
                result.put("message", rs.getString("out_message"));
                return result;
            }
            return null;
        });
    }

    public Map<String, Object> getAccountSummary(String accountNumber) {
        String sql = """
            SELECT a.account_number, a.customer_id, a.account_id, a.type AS account_type, a.status AS account_status,a.current_balance, a.hold_balance, a.available_balance, a.ifsc_code, a.average_spends, c.cif_number, c.first_name || ' ' || c.last_name AS customer_name,c.phone, c.email, c.kyc_status, c.dob, c.age, c.gender, c.pan_number, c.address_line1, c.address_line2, c.city, c.state, c.country, c.pincode, c.created_at, c.updated_at, c.device_id                                                                                   
            FROM accounts a
            JOIN customers c ON a.customer_id = c.customer_id
            WHERE a.account_number = :accNum
        """;
        try {
            return jdbcTemplate.queryForMap(sql, Map.of("accNum", accountNumber));
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            return null;
        }
    }

    // 3. Check Payment Status by UTR Number
    public Map<String, Object> getTransactionStatusByUtr(String utrNumber) {
        String sql = """
            SELECT 
                payment_id, utr_number, idempotency_key,
                debit_account_number AS sender_account,
                credit_account_number AS receiver_account,
                amount, currency, payment_mode, status,
                failure_reason, reference_note, created_at, completed_at
            FROM payments
            WHERE utr_number = :utr
        """;
        try {
            return jdbcTemplate.queryForMap(sql, Map.of("utr", utrNumber));
        } catch (org.springframework.dao.EmptyResultDataAccessException e) {
            return null;
        }
    }

    // 4. Fetch Passbook / Statement for an Account
    public List<Map<String, Object>> getAccountStatement(String accountNumber, int limit) {
        String sql = """
            SELECT 
                l.created_at AS transaction_time,
                p.utr_number,
                l.direction,
                CASE WHEN l.direction = 'DEBIT' THEN -ABS(l.amount) ELSE ABS(l.amount) END AS transaction_amount,
                l.opening_balance,
                l.closing_balance,
                l.counterparty_account_number,
                p.status AS payment_status,
                l.narration
            FROM ledger_entries l
            JOIN payments p ON l.payment_id = p.payment_id
            WHERE l.account_number = :accNum
            ORDER BY l.created_at DESC
            LIMIT :lim
        """;
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("accNum", accountNumber)
                .addValue("lim", limit);
        return jdbcTemplate.queryForList(sql, params);
    }
}