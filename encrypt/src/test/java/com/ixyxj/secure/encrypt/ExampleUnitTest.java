package com.ixyxj.secure.encrypt;

import org.junit.Test;

/**
 * Example local unit test, which will execute on the development machine (host).
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
public class ExampleUnitTest {
    @Test
    public void addition_isCorrect() {
        System.out.println(EncryptFactory.get().encrypt("xyxj"));
        System.out.println(EncryptFactory.get().decrypt("eHl4ag=="));
        EncryptFactory.get().setType(EncryptFactory.TYPE_AES);

        System.out.println(EncryptFactory.get().encrypt("xyxj"));
        System.out.println(EncryptFactory.get().decrypt("8483FC4D675B080D95A8A360A8091E48"));
        //EncryptFactory.get().setEncrypt(xxx);
    }
}