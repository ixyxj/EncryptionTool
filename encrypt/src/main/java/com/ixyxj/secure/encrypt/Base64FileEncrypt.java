package com.ixyxj.secure.encrypt;

import android.text.TextUtils;

import com.ixyxj.secure.encrypt.base.Base64;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import static com.ixyxj.secure.encrypt.Utils.close;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 0:23
 * Copyright (c) 2019 in FORETREE
 */
public class Base64FileEncrypt implements FileEncrypt<String> {
    private String filePath;

    public Base64FileEncrypt(String filePath) {
        this.filePath = filePath;
    }

    @Override
    public String encrypt(File decrypt) {
        if (null == decrypt) return "";

        FileInputStream inputFile = null;
        try {
            inputFile = new FileInputStream(decrypt);
            byte[] buffer = new byte[(int) decrypt.length()];
            inputFile.read(buffer);
            return Base64.encodeToString(buffer, Base64.DEFAULT);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            close(inputFile);
        }
        return "";
    }

    @Override
    public File decrypt(String encrypt) {
        if (TextUtils.isEmpty(filePath) || TextUtils.isEmpty(encrypt)) {
            return null;
        }
        FileOutputStream fos = null;
        File desFile = new File(filePath);
        try {
            byte[] decodeBytes = Base64.decode(encrypt.getBytes(), Base64.DEFAULT);
            fos = new FileOutputStream(desFile);
            fos.write(decodeBytes);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            close(fos);
        }
        return desFile;
    }
}
