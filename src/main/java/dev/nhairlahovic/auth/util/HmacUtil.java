package dev.nhairlahovic.auth.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class HmacUtil {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public static String generateHmac(String data, String key) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), HMAC_ALGORITHM);
            mac.init(secretKeySpec);

            byte[] hmacBytes = mac.doFinal(data.getBytes()); // Compute HMAC
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hmacBytes); // Encode in Base64
        } catch (Exception e) {
            throw new RuntimeException("Error while generating HMAC", e);
        }
    }
}
