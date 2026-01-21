package com.eidiko.app.encryptanddecrypt.Controller;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.eidiko.app.encryptanddecrypt.Model.EncryptRequest;
import com.eidiko.app.encryptanddecrypt.Model.EncryptResponse;
import com.eidiko.app.encryptanddecrypt.Service.CryptoUtil;
import org.springframework.beans.factory.annotation.Value;


@RestController
@RequestMapping("/crypto")
public class EncryptionController {

    private final CryptoUtil cryptoUtil;

    @Value("${app.public.key}")
    private String serverPublicKey;

    public EncryptionController(CryptoUtil cryptoUtil) {
        this.cryptoUtil = cryptoUtil;
    }

    @PostMapping("/encrypt")
    public EncryptResponse encrypt(@RequestBody String plainJson) throws Exception {

        // 1. Generate AES key
        SecretKey aesKey = cryptoUtil.generateAESKey();

        // 2. Encrypt the JSON with AES
        String encryptedData = cryptoUtil.aesEncrypt(plainJson, aesKey);

        // 3. Encrypt AES key with RSA
        PublicKey publicKey = cryptoUtil.loadPublicKey(serverPublicKey);
        String encryptedKey = cryptoUtil.rsaEncryptAESKey(aesKey, publicKey);

        // 4. Combine both with a separator (e.g., "::")
        String combined = encryptedKey + "::" + encryptedData;

        EncryptResponse response = new EncryptResponse();
        response.setCombinedData(combined);
        return response;
    }
}