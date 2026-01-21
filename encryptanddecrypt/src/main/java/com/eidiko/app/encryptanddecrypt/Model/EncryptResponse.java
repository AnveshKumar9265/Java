package com.eidiko.app.encryptanddecrypt.Model;

public class EncryptResponse {
     private String combinedData; // single field containing both encryptedKey + encryptedData

    public String getCombinedData() {
        return combinedData;
    }

    public void setCombinedData(String combinedData) {
        this.combinedData = combinedData;
    }
}