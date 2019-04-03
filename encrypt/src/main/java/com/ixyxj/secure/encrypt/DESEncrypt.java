package com.ixyxj.secure.encrypt;

import android.annotation.SuppressLint;

import com.ixyxj.secure.encrypt.base.IntDef;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import static com.ixyxj.secure.encrypt.Utils.parseByte2HexStr;
import static com.ixyxj.secure.encrypt.Utils.parseHexStr2Byte;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 1:04
 * Copyright (c) 2019 in FORETREE
 * <p>
 * 对称加密算法
 */
public class DESEncrypt implements Encrypt<String, String> {
    @IntDef({Cipher.ENCRYPT_MODE, Cipher.DECRYPT_MODE})
    @interface DESType {
    }

    private String pwd;

    public DESEncrypt() {
        this("");
    }

    public DESEncrypt(String pwd) {
        this.pwd = pwd;
    }

    @Override
    public String encrypt(String decrypt) {
        return des(decrypt, pwd, Cipher.ENCRYPT_MODE);
    }

    @Override
    public String decrypt(String encrypt) {
        return des(encrypt, pwd, Cipher.DECRYPT_MODE);
    }

    /**
     * Des加密/解密
     *
     * @param content  字符串内容
     * @param password 密钥
     * @param type     加密：{@link Cipher#ENCRYPT_MODE}，解密：{@link Cipher#DECRYPT_MODE}
     * @return 加密/解密结果
     */
    public static String des(String content, String password, @DESType int type) {
        try {
            SecureRandom random = new SecureRandom();
            DESKeySpec desKey = new DESKeySpec(password.getBytes());
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            @SuppressLint("GetInstance") Cipher cipher = Cipher.getInstance("DES");
            cipher.init(type, keyFactory.generateSecret(desKey), random);

            if (type == Cipher.ENCRYPT_MODE) {
                byte[] byteContent = content.getBytes("utf-8");
                return parseByte2HexStr(cipher.doFinal(byteContent));
            } else {
                byte[] byteContent = parseHexStr2Byte(content);
                return new String(cipher.doFinal(byteContent));
            }
        } catch (NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException |
                UnsupportedEncodingException | InvalidKeyException | NoSuchPaddingException |
                InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return "";
    }
}
