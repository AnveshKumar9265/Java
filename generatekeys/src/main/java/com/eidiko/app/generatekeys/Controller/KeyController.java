package com.eidiko.app.generatekeys.Controller;
import com.eidiko.app.generatekeys.Utility.RSAKeyGenerator;
import  com.eidiko.app.generatekeys.Utility.RSAKeyGenerator.*;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class KeyController {
    @GetMapping("/generate-keys")
    public Map<String, String> generateKeys() throws Exception {
        KeyPair pair = RSAKeyGenerator.generateKeyPair();

        Map<String, String> response = new HashMap<>();
        response.put("publicKey", RSAKeyGenerator.getPublicKeyBase64(pair));
        response.put("privateKey", RSAKeyGenerator.getPrivateKeyBase64(pair));

        return response;
    }
}
