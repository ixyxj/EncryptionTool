package com.ixyxj.secure.encrypt;

import com.ixyxj.secure.encrypt.base.StringDef;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 1:36
 * Copyright (c) 2019 in FORETREE
 */
public class EncryptFactory {
    public final static String TYPE_BASE64 = "Base64Encrypt";
    public final static String TYPE_MD5 = "MD5Encrypt";
    public final static String TYPE_SHA = "SHAEncrypt";
    public final static String TYPE_AES = "AESEncrypt";
    public final static String TYPE_DES = "DESEncrypt";
    public final static String TYPE_RSA = "RSAEncrypt";

    @StringDef({TYPE_BASE64, TYPE_MD5, TYPE_SHA, TYPE_AES, TYPE_DES, TYPE_RSA})
    private @interface EncryptType {
    }

    private static EncryptFactory mFactory;
    private Encrypt encrypt;

    private EncryptFactory() {
    }

    public static EncryptFactory get() {
        if (mFactory == null) {
            synchronized (EncryptFactory.class) {
                if (mFactory == null) {
                    mFactory = new EncryptFactory();
                    mFactory.encrypt = new Base64Encrypt();//默认是base64加密
                }
            }
        }
        return mFactory;
    }

    public void setType(@EncryptType String clz) {
        String rePath = "com.ixyxj.secure.encrypt.";
        try {
            this.encrypt = (Encrypt) Class.forName(rePath.concat(clz)).newInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 设置加密方式
     *
     * @param encrypt
     */
    public void setEncrypt(Encrypt encrypt) {
        this.encrypt = encrypt;
    }

    public String encrypt(String en) {
        if (encrypt == null) return "";
        return (String) encrypt.encrypt(en);
    }

    public String decrypt(String de) {
        if (encrypt == null) return "";
        return (String) encrypt.decrypt(de);
    }

}
