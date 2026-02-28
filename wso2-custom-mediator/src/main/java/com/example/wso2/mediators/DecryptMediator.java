package com.example.wso2.mediators;

import org.apache.synapse.MessageContext;
import org.apache.synapse.mediators.AbstractMediator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class DecryptMediator extends AbstractMediator {
    
    private static Log log = LogFactory.getLog(DecryptMediator.class);

    private String EncryptedText;

    // Field to receive the secret key
    private String SecretKey;

    // Setter for the encrypted text from synapse class mediator property
    public void setEncryptedText(String EncryptedText) {
        this.EncryptedText = EncryptedText;
    }

    // Setter for the secret key from synapse class mediator property
    public void setSecretKey(String SecretKey) {
        this.SecretKey = SecretKey;
    }

    @Override
    public boolean mediate(MessageContext messageContext) {
        try {
            log.info("Decrypting payload");

            // Perform decryption with AES utility
            String decrypted = AesCryptoUtil.decrypt(EncryptedText, SecretKey);

            // Place decrypted output into message context
            messageContext.setProperty("DECRYPTED_PAYLOAD", decrypted);

            log.info("Payload decrypted successfully");
        } catch (Exception e) {
            log.error("Error in DecryptMediator", e);
            return false;
        }
        return true;
    }
}