package com.ixyxj.secure.encrypt;

import com.ixyxj.secure.encrypt.base.StringDef;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.ixyxj.secure.encrypt.Utils.isEmpty;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 0:53
 * Copyright (c) 2019 in FORETREE
 * one way
 */
public class SHAEncrypt implements Encrypt<String, String> {
    public final static String SHA224 = "sha-224";
    public final static String SHA256 = "sha-256";
    public final static String SHA384 = "sha-384";
    public final static String SHA512 = "sha-512";

    @StringDef({SHA224, SHA256, SHA384, SHA512})
    @interface SHAType {}

    private String type;

    public SHAEncrypt() {
        this(SHA256);
    }

    public SHAEncrypt(@SHAType String type) {
        this.type = type;
    }

    @Override
    public String encrypt(String decrypt) {
        return sha(decrypt, type);
    }

    @Override
    public String decrypt(String encrypt) {
        return "";//不可逆
    }

    /**
     * Sha加密
     *
     * @param string 加密字符串
     * @param type   加密类型 ：{@link #SHA224}，{@link #SHA256}，{@link #SHA384}，{@link #SHA512}
     * @return SHA加密结果字符串
     */
    public static String sha(String string, @SHAType String type) {
        if (isEmpty(string)) return "";
        if (isEmpty(type)) type = SHA256;

        try {
            MessageDigest md5 = MessageDigest.getInstance(type);
            byte[] bytes = md5.digest((string).getBytes());
            String result = "";
            for (byte b : bytes) {
                String temp = Integer.toHexString(b & 0xff);
                if (temp.length() == 1) {
                    temp = "0" + temp;
                }
                result += temp;
            }
            return result;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return "";
    }
}
