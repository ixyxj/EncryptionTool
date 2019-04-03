package com.ixyxj.secure.encrypt;

import android.os.Build;

import com.ixyxj.secure.encrypt.base.Base64;
import com.ixyxj.secure.encrypt.base.IntDef;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

import static com.ixyxj.secure.encrypt.Utils.close;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 1:09
 * Copyright (c) 2019 in FORETREE
 */
public class RSAEncrypt implements Encrypt<byte[], byte[]> {
    /**
     * Rsa公钥加密类型
     */
    public static final int RSA_PUBLIC_ENCRYPT = 0;

    /**
     * Rsa公钥解密类型
     */
    public static final int RSA_PUBLIC_DECRYPT = 1;

    /**
     * Rsa私钥加密类型
     */
    public static final int RSA_PRIVATE_ENCRYPT = 2;

    /**
     * Rsa私钥解密类型
     */
    public static final int RSA_PRIVATE_DECRYPT = 3;

    @IntDef({RSA_PUBLIC_ENCRYPT, RSA_PUBLIC_DECRYPT, RSA_PRIVATE_ENCRYPT, RSA_PRIVATE_DECRYPT})
    @interface RSAType {
    }

    private String publicKey, privateKey;
    private boolean isEncryptionByPublic;//是否公钥加密, 默认是false

    public RSAEncrypt() {
        initKey();
    }


    public RSAEncrypt(boolean isEncryptionByPublic) {
        initKey();
        this.isEncryptionByPublic = isEncryptionByPublic;
    }

    public RSAEncrypt(String publicKey, String privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public byte[] encrypt(byte[] decrypt) {
        return rsa(decrypt, isEncryptionByPublic ? publicKey : privateKey,
                isEncryptionByPublic ? RSA_PUBLIC_ENCRYPT : RSA_PRIVATE_ENCRYPT);
    }

    @Override
    public byte[] decrypt(byte[] encrypt) {
        return rsa(encrypt, isEncryptionByPublic ? privateKey : publicKey,
                isEncryptionByPublic ? RSA_PRIVATE_DECRYPT : RSA_PUBLIC_DECRYPT);
    }

    // 密钥与数字签名获取
    private void initKey() {
        Map<String, Object> keyMap = getKeyPair();
        this.publicKey = getKey(keyMap, true);
        this.privateKey = getKey(keyMap, false);
    }

    /**
     * Rsa加密/解密（一般情况下，公钥加密私钥解密）
     *
     * @param data   源数据
     * @param string 密钥(BASE64编码)
     * @param type   操作类型：{@link #RSA_PUBLIC_ENCRYPT}，{@link #RSA_PUBLIC_DECRYPT
     *               }，{@link #RSA_PRIVATE_ENCRYPT}，{@link #RSA_PRIVATE_DECRYPT}
     * @return 加密/解密结果字符串
     * @throws Exception 异常
     */
    private byte[] rsa(byte[] data, String string, @RSAType int type) {
        byte[] keyBytes = Base64.decode(string, Base64.DEFAULT);


        ByteArrayOutputStream out = null;
        byte[] result = new byte[0];
        try {
            Key key;
            KeyFactory keyFactory = getKeyFactory();

            if (type == RSA_PUBLIC_ENCRYPT || type == RSA_PUBLIC_DECRYPT) {
                X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
                key = keyFactory.generatePublic(x509KeySpec);
            } else {
                PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
                key = keyFactory.generatePrivate(pkcs8KeySpec);
            }
            // 对数据加密
            Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
            int inputLen = data.length;
            out = new ByteArrayOutputStream();
            int offSet = 0;
            byte[] cache;
            int i = 0;

            // 对数据分段加密
            if (type == RSA_PUBLIC_ENCRYPT || type == RSA_PRIVATE_ENCRYPT) {
                cipher.init(Cipher.ENCRYPT_MODE, key);

                while (inputLen - offSet > 0) {
                    if (inputLen - offSet > 117) {
                        cache = cipher.doFinal(data, offSet, 117);
                    } else {
                        cache = cipher.doFinal(data, offSet, inputLen - offSet);
                    }

                    out.write(cache, 0, cache.length);
                    out.flush();
                    i++;
                    offSet = i * 117;
                }
            } else {
                cipher.init(Cipher.DECRYPT_MODE, key);
                while (inputLen - offSet > 0) {
                    if (inputLen - offSet > 128) {
                        cache = cipher.doFinal(data, offSet, 128);
                        // 当最前面的数据是0，解密工具会错误的认为这是padding，因此导致长度不正确
                        if (cache.length < 117) {
                            byte[] temp = new byte[117];
                            System.arraycopy(cache, 0, temp, 117 - cache.length, cache.length);
                            cache = temp;
                        }
                    } else {
                        cache = cipher.doFinal(data, offSet, inputLen - offSet);
                    }
                    out.write(cache, 0, cache.length);
                    out.flush();
                    i++;
                    offSet = i * 128;
                }
            }
            result = out.toByteArray();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (out != null)
                close(out);
        }
        return result;
    }

    /**
     * 随机获取密钥(公钥和私钥), 客户端公钥加密，服务器私钥解密
     *
     * @return 结果密钥对
     * @throws Exception 异常
     */
    public Map<String, Object> getKeyPair() {
        Map<String, Object> keyMap = new HashMap<>(2);
        try {
            KeyPairGenerator keyPairGen = getKeyPairGenerator();
            keyPairGen.initialize(1024);
            KeyPair keyPair = keyPairGen.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            keyMap.put("RSAPublicKey", publicKey);
            keyMap.put("RSAPrivateKey", privateKey);
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return keyMap;
    }

    /**
     * 获取公钥/私钥
     *
     * @param keyMap      密钥对
     * @param isPublicKey true：获取公钥，false：获取私钥
     * @return 获取密钥字符串
     */
    private String getKey(Map<String, Object> keyMap, boolean isPublicKey) {
        Key key = (Key) keyMap.get(isPublicKey ? "RSAPublicKey" : "RSAPrivateKey");
        if (key == null) return "";
        return new String(Base64.encode(key.getEncoded(), Base64.DEFAULT));
    }

    /**
     * 获取数字签名
     *
     * @param data       二进制位
     * @param privateKey 私钥(BASE64编码)
     * @return 数字签名结果字符串
     * @throws Exception 异常
     */
    public String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.decode(privateKey.getBytes(), Base64.DEFAULT);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = getKeyFactory();
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);

        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(privateK);
        signature.update(data);
        return new String(Base64.encode(signature.sign(), Base64.DEFAULT));
    }

    /**
     * 数字签名校验
     *
     * @param data      二进位组
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名字符串
     * @return true：校验成功，false：校验失败
     * @throws Exception 异常
     */
    public boolean verify(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = Base64.decode(publicKey.getBytes(), Base64.DEFAULT);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = getKeyFactory();
        PublicKey publicK = keyFactory.generatePublic(keySpec);

        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64.decode(sign.getBytes(), Base64.DEFAULT));
    }

    /**
     * 获取 KeyFactory
     *
     * @throws NoSuchAlgorithmException 异常
     */
    private KeyFactory getKeyFactory() throws NoSuchAlgorithmException,
            NoSuchProviderException {
        KeyFactory keyFactory;
        if (Build.VERSION.SDK_INT >= 16) {
            keyFactory = KeyFactory.getInstance("RSA", "BC");
        } else {
            keyFactory = KeyFactory.getInstance("RSA");
        }
        return keyFactory;
    }

    /**
     * 获取 KeyFactory
     *
     * @throws NoSuchAlgorithmException 异常
     */
    private KeyPairGenerator getKeyPairGenerator() throws NoSuchProviderException,
            NoSuchAlgorithmException {
        KeyPairGenerator keyPairGen;
        if (Build.VERSION.SDK_INT >= 16) {
            keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
        } else {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
        }
        return keyPairGen;
    }
}
