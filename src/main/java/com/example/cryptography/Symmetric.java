package com.example.cryptography;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Symmetric extends AppCompatActivity {

    private final static String TAG = MainActivity.class.getCanonicalName();
    String myKey = "TheThirtyTwoByteKeyForEncryption";
    byte[] encrypted;
    String dataToEncrypt;
    byte[] initializationVector = null;
    EditText key;
    EditText text;
    EditText ans;

    @Override
    protected void onCreate(Bundle savedInstanceState) {

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_symmetric);
        key = findViewById(R.id.symmetric_key);
        text = findViewById(R.id.symmetric_text);
        ans = findViewById(R.id.symmetric_ans);

        byte[] initializationVector = null;
        try {

            initializationVector = CRDCrypt.generateInitializationVector();

        } catch (CRDCryptException e) {

            Log.e(TAG, "onCreate: failed to create initialization vector", e);
        }
    }
    public void onEncrypt(View view) throws UnsupportedEncodingException {
        dataToEncrypt=text.getText().toString();
        myKey=key.getText().toString();
        encrypted = null;
        try {

            encrypted = CRDCrypt.aes256Encrypt(myKey, dataToEncrypt.getBytes("UTF-8"), initializationVector);

        } catch (UnsupportedEncodingException e) {

            Log.e(TAG, "onCreate: failed to encode data to encrypt", e);

        } catch (CRDCryptException e) {

            Log.e(TAG, "onCreate: failed to encrypt data", e);
        }
        ans.setText(new String(encrypted,"UTF-8"));

    }

    public void onDecrypt(View view) {

        byte[] decrypted = null;
        try {

            decrypted = CRDCrypt.aes256Decrypt(myKey, encrypted, initializationVector);

        } catch (CRDCryptException e) {

            Log.e(TAG, "onCreate: failed to decrypt data", e);
        }

        // Get the string from the decrypted data.
        String transformedData = null;
        try {

            transformedData = new String(decrypted, "UTF-8");

        } catch (UnsupportedEncodingException e) {

            Log.e(TAG, "onCreate: failed to decode decrypted data to string", e);
        }

        // Decrypted data should be the same as the original data encrypted.
        if (transformedData.equals(dataToEncrypt)) {

            Log.i(TAG, "onCreate: SUCCESS! decrypted data is equal to original data.");

        } else {

            Log.e(TAG, "onCreate: FAILED! decrypted data is not equal to original data");

    }
        ans.setText(transformedData);
    }
}

class CRDCrypt {

    private static final String TAG = CRDCrypt.class.getCanonicalName();


    private static final String PROVIDER_IV = "AES/CBC/PKCS5Padding";


    private static final String PROVIDER_NO_IV = "AES/ECB/PKCS5Padding";


    public static byte[] generateInitializationVector() throws CRDCryptException {

        SecureRandom random = new SecureRandom();
        Cipher cipher;
        try {

            cipher = Cipher.getInstance(PROVIDER_IV);

        } catch (NoSuchAlgorithmException e) {

            throw new CRDCryptException(TAG, "generateInitializationVector", "encryption algorithm not available", e);

        } catch (NoSuchPaddingException e) {

            throw new CRDCryptException(TAG, "generateInitializationVector", "padding algorithm not available", e);
        }

        byte[] realIV = new byte[cipher.getBlockSize()];
        random.nextBytes(realIV);
        return realIV;
    }


    public static byte[] aes256Encrypt(String key, byte[] decrypted, byte[] initializationVector) throws CRDCryptException {

        if (key == null || key.length() == 0) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "specified key is null or empty");
        }

        if (decrypted == null || decrypted.length == 0) {

            // Nothing to do.
            return decrypted;
        }

        // Produce the hashed key for decryption based on the specified key.
        byte[] hashedKey;
        try {

            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            hashedKey = sha.digest(key.getBytes("UTF-8"));

        } catch (NoSuchAlgorithmException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "message digest algorithm not available", e);

        } catch (UnsupportedEncodingException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "failed to encode key with UTF-8", e);
        }

        SecretKeySpec secretKeySpec;
        try {

            secretKeySpec = new SecretKeySpec(hashedKey, "AES");

        } catch (IllegalArgumentException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "hashed key is invalid", e);
        }

        IvParameterSpec ivSpec = null;
        if (initializationVector != null && initializationVector.length > 0) {

            ivSpec = new IvParameterSpec(initializationVector);
        }

        // Encode the original data with AES
        Cipher cipher;
        if (ivSpec == null) {

            try {

                cipher = Cipher.getInstance(PROVIDER_NO_IV);

            } catch (NoSuchAlgorithmException e) {

                throw new CRDCryptException(TAG, "aes256Encrypt", "encryption algorithm not available", e);

            } catch (NoSuchPaddingException e) {

                throw new CRDCryptException(TAG, "aes256Encrypt", "padding algorithm not available", e);
            }

        } else {

            try {

                cipher = Cipher.getInstance(PROVIDER_IV);

            } catch (NoSuchAlgorithmException e) {

                throw new CRDCryptException(TAG, "aes256Encrypt", "encryption algorithm not available", e);

            } catch (NoSuchPaddingException e) {

                throw new CRDCryptException(TAG, "aes256Encrypt", "padding algorithm not available", e);
            }
        }

        try {

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        } catch (InvalidKeyException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "invalid secret key spec", e);

        } catch (InvalidAlgorithmParameterException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "invalid encryption parameter", e);
        }

        try {

            byte[] encodedBytes = cipher.doFinal(decrypted);
            return encodedBytes;

        } catch (IllegalBlockSizeException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "illegal block size", e);

        } catch (BadPaddingException e) {

            throw new CRDCryptException(TAG, "aes256Encrypt", "invalid padding", e);
        }
    }


    public static byte[] aes256Encrypt(String key, byte[] decrypted) throws CRDCryptException {

        return aes256Encrypt(key, decrypted, null);
    }


    public static byte[] aes256Decrypt(String key, byte[] encrypted, byte[] initializationVector) throws CRDCryptException {

        if (key == null || key.length() == 0) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "specified key is null or empty");
        }

        if (encrypted == null || encrypted.length == 0) {

            // Nothing to do.
            return encrypted;
        }

        // Produce the hashed key for decryption based on the specified key.
        byte[] hashedKey;
        try {

            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            hashedKey = sha.digest(key.getBytes("UTF-8"));

        } catch (NoSuchAlgorithmException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "message digest algorithm not available", e);

        } catch (UnsupportedEncodingException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "failed to encode key with UTF-8", e);
        }

        SecretKeySpec secretKeySpec;
        try {

            secretKeySpec = new SecretKeySpec(hashedKey, "AES");

        } catch (IllegalArgumentException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "hashed key is invalid", e);
        }

        IvParameterSpec ivSpec = null;
        if (initializationVector != null && initializationVector.length > 0) {

            ivSpec = new IvParameterSpec(initializationVector);
        }

        // Decode the encoded data with AES
        Cipher cipher;
        if (ivSpec == null) {

            try {

                cipher = Cipher.getInstance(PROVIDER_NO_IV);

            } catch (NoSuchAlgorithmException e) {

                throw new CRDCryptException(TAG, "aes256Decrypt", "encryption algorithm not available", e);

            } catch (NoSuchPaddingException e) {

                throw new CRDCryptException(TAG, "aes256Decrypt", "padding algorithm not available", e);
            }

        } else {

            try {

                cipher = Cipher.getInstance(PROVIDER_IV);

            } catch (NoSuchAlgorithmException e) {

                throw new CRDCryptException(TAG, "aes256Decrypt", "encryption algorithm not available", e);

            } catch (NoSuchPaddingException e) {

                throw new CRDCryptException(TAG, "aes256Decrypt", "padding algorithm not available", e);
            }
        }

        try {

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);

        } catch (InvalidKeyException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "invalid secret key spec", e);

        } catch (InvalidAlgorithmParameterException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "invalid encryption parameter", e);
        }

        try {

            byte[] decodedBytes = cipher.doFinal(encrypted);
            return decodedBytes;

        } catch (IllegalBlockSizeException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "illegal block size", e);

        } catch (BadPaddingException e) {

            throw new CRDCryptException(TAG, "aes256Decrypt", "invalid padding", e);
        }
    }


    public static byte[] aes256Decrypt(String myKey, String key, byte[] encrypted) throws CRDCryptException {

        return aes256Decrypt(key, encrypted, null);
    }
}
class CRDCryptException extends Exception {


    private static final String TAG = CRDCryptException.class.getCanonicalName();

    private String className = null;


    private String methodName = null;


    private Exception underlyingException = null;


    public CRDCryptException(String className, String methodName, String message, Exception underlyingException) {

        // Call the super class to instantiate the exception, passing the given message to use.
        super(message);

        this.className = className;
        this.methodName = methodName;
        this.underlyingException = underlyingException;
    }


    public CRDCryptException(String className, String methodName, String message) {

        // Call the super class to instantiate the exception, passing the given message to use.
        super(message);

        this.className = className;
        this.methodName = methodName;
    }


    public String getClassName() {

        return className;
    }


    public String getMethodName() {

        return methodName;
    }


    public Exception getUnderlyingException() {

        return underlyingException;
    }

    //endregion
}


