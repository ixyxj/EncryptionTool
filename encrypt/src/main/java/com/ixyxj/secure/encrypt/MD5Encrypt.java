package com.ixyxj.secure.encrypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static com.ixyxj.secure.encrypt.Utils.isEmpty;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 0:33
 * Copyright (c) 2019 in FORETREE
 * one way
 */
public class MD5Encrypt implements Encrypt<String, String> {
    private String salt;
    private int times;

    public MD5Encrypt() {
        this("", 1);
    }

    public MD5Encrypt(String salt) {
        this(salt, 1);
    }

    public MD5Encrypt(String salt, int times) {
        this.salt = salt;
        this.times = times;
    }

    @Override
    public String encrypt(String decrypt) {
        return isEmpty(decrypt) ? "" : md5(decrypt, salt, times);
    }

    @Override
    public String decrypt(String encrypt) {
        return "";//md5不可逆
    }

    /**
     * MD5加密(加盐)
     *
     * @param str 加密字符串
     * @param slat   加密盐值key
     * @param times 迭代次数, 不能为0
     * @return 加密结果字符串
     */
    private String md5(String str, String slat, int times) {
        String result = "";
        if (isEmpty(str)) return result;
        try {
            result = str;
            if (times <= 0) times = 1;
            for (int i = 0; i < times; i++) {
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                byte[] bytes = md5.digest((result + slat).getBytes());
                StringBuilder sb = new StringBuilder();
                for (byte b : bytes) {
                    String temp = Integer.toHexString(b & 0xff);
                    if (temp.length() == 1) {
                        temp = "0" + temp;
                    }
                    sb.append(temp);
                }
                result = sb.toString();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return result;
    }
}
