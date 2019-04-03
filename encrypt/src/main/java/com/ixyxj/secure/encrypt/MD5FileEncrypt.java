package com.ixyxj.secure.encrypt;

import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;

import static com.ixyxj.secure.encrypt.Utils.close;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 0:51
 * Copyright (c) 2019 in FORETREE
 */
public class MD5FileEncrypt implements FileEncrypt<String> {

    @Override
    public String encrypt(File decrypt) {
        return md5(decrypt);
    }

    @Override
    public File decrypt(String encrypt) {
        return null;
    }

    /**
     * MD5加密(文件)
     * 可用于文件校验。
     *
     * @param file 加密文件
     * @return md5 数值
     */
    private String md5(File file) {
        if (!file.isFile()) {
            return "";
        }
        MessageDigest digest = null;
        FileInputStream in = null;
        byte buffer[] = new byte[1024];
        int len;
        try {
            digest = MessageDigest.getInstance("MD5");
            in = new FileInputStream(file);
            while ((len = in.read(buffer, 0, 1024)) != -1) {
                digest.update(buffer, 0, len);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        } finally {
            close(in);
        }
        BigInteger bigInt = new BigInteger(1, digest.digest());
        return bigInt.toString(16);
    }
}
