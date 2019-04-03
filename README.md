# EncryptionTool
:boom 常见加密算法

### 常见算法:
- TYPE_BASE64
- TYPE_MD5
- TYPE_SHA
- TYPE_AES
- TYPE_DES
- TYPE_RSA

### 使用说明:
初始化:
```java
//默认base64编码
System.out.println(EncryptFactory.get().encrypt("xyxj"));
System.out.println(EncryptFactory.get().decrypt("eHl4ag=="));
```
设置类型:
```java
EncryptFactory.get().setType(EncryptFactory.TYPE_AES);
System.out.println(EncryptFactory.get().encrypt("xyxj"));
System.out.println(EncryptFactory.get().decrypt("8483FC4D675B080D95A8A360A8091E48"));
```

自定义类型: 继承自Encrypt
```
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
}
```
然后设置到 
```
EncryptFactory.get().setEncrypt(xxx);
```


