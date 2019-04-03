package com.ixyxj.secure.encrypt;

import com.ixyxj.secure.encrypt.base.Base64;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 0:14
 * Copyright (c) 2019 in FORETREE
 */
public class Base64Encrypt implements Encrypt<String, String> {

    public Base64Encrypt() {
    }

    @Override
    public String encrypt(String decrypt) {
        if (Utils.isEmpty(decrypt))return "";
        return Base64.encodeToString(decrypt.getBytes(), Base64.DEFAULT);
    }

    @Override
    public String decrypt(String encrypt) {
        if (Utils.isEmpty(encrypt)) return "";
        return new String(Base64.decode(encrypt, Base64.DEFAULT));
    }
}
