package com.ixyxj.secure.encrypt;

import android.annotation.SuppressLint;

import com.ixyxj.secure.encrypt.base.CryptoProvider;
import com.ixyxj.secure.encrypt.base.IntDef;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static com.ixyxj.secure.encrypt.Utils.parseByte2HexStr;
import static com.ixyxj.secure.encrypt.Utils.parseHexStr2Byte;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 0:58
 * Copyright (c) 2019 in FORETREE
 */
public class AESEncrypt implements Encrypt<String, String> {

    private final static String SHA1PRNG = "SHA1PRNG";

    @IntDef({Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
    @interface AESType {
    }

    private String pwd;

    public AESEncrypt() {
        this("");
    }

    public AESEncrypt(String pwd) {
        this.pwd = pwd;
    }

    @Override
    public String encrypt(String decrypt) {
        return aes(decrypt, pwd, Cipher.ENCRYPT_MODE);
    }

    @Override
    public String decrypt(String encrypt) {
        return aes(encrypt, pwd, Cipher.DECRYPT_MODE);
    }

    /**
     * Aes加密/解密
     *
     * @param content  字符串
     * @param password 密钥
     * @param type     加密：{@link Cipher#ENCRYPT_MODE}，解密：{@link Cipher#DECRYPT_MODE}
     * @return 加密/解密结果字符串
     */
    @SuppressLint("DeletedProvider")
    private String aes(String content, String password, @AESType int type) {
        try {
            KeyGenerator generator = KeyGenerator.getInstance("AES");

            SecureRandom secureRandom;
            if (android.os.Build.VERSION.SDK_INT >= 24) {
                secureRandom = SecureRandom.getInstance(SHA1PRNG, new CryptoProvider());
            } else if (android.os.Build.VERSION.SDK_INT >= 17) {
                secureRandom = SecureRandom.getInstance(SHA1PRNG, "Crypto");
            } else {
                secureRandom = SecureRandom.getInstance(SHA1PRNG);
            }
            secureRandom.setSeed(password.getBytes());
            generator.init(128, secureRandom);
            SecretKey secretKey = generator.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            @SuppressLint("GetInstance") Cipher cipher = Cipher.getInstance("AES");
            cipher.init(type, key);

            if (type == Cipher.ENCRYPT_MODE) {
                byte[] byteContent = content.getBytes(Charset.forName("UTF-8"));
                return parseByte2HexStr(cipher.doFinal(byteContent));
            } else {
                byte[] byteContent = parseHexStr2Byte(content);
                return new String(cipher.doFinal(byteContent));
            }
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException |
                InvalidKeyException | NoSuchPaddingException |
                NoSuchProviderException e) {
            e.printStackTrace();
        }
        return null;
    }
}
