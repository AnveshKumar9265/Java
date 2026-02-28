package com.example.wso2.mediators;

import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class EncryptMediator extends AbstractMediator {

    private static Log log = LogFactory.getLog(EncryptMediator.class);
    private String originalText;
    private String secretKey;

    // setter for OriginalText
    public void setOriginalText(String originalText) {
        this.originalText = originalText;
    }

    // setter for SecretKey
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    @Override
    public boolean mediate(MessageContext mc) {
        try {
            String encrypted = AesCryptoUtil.encrypt(originalText, secretKey);
            mc.setProperty("ENCRYPTED_PAYLOAD", encrypted);
        } catch (Exception e) {
            log.error("Error", e);
            return false;
        }
        return true;
    }
}