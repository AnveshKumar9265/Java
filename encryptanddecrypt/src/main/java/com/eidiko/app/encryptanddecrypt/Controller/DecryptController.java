package com.eidiko.app.encryptanddecrypt.Controller;

import javax.crypto.SecretKey;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.eidiko.app.encryptanddecrypt.Model.DecryptRequest;
import com.eidiko.app.encryptanddecrypt.Model.DecryptResponse;
import com.eidiko.app.encryptanddecrypt.Service.CryptoUtil;

@RestController
@RequestMapping("/crypto")
public class DecryptController {

    private final CryptoUtil cryptoUtil;

    public DecryptController(CryptoUtil cryptoUtil) {
        this.cryptoUtil = cryptoUtil;
    }

    @PostMapping("/decrypt")
    public DecryptResponse decrypt(@RequestBody DecryptRequest request) throws Exception {

        // 1. Split the combined data
        String[] parts = request.getCombinedData().split("::", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid combined data format");
        }

        String encryptedKey = parts[0];
        String encryptedData = parts[1];

        // 2. Decrypt AES key
        SecretKey aesKey = cryptoUtil.rsaDecryptAESKey(encryptedKey);

        // 3. Decrypt JSON
        String plainJson = cryptoUtil.aesDecrypt(encryptedData, aesKey);

        DecryptResponse response = new DecryptResponse();
        response.setPlainJson(plainJson);
        return response;
    }
}
