package com.ixyxj.secure.encrypt;

/**
 * For more information, you can visit https://github.com/ixyxj,
 * or contact me by xyxjun@gmail.com
 *
 * @author silen on 2019/4/4 0:04
 * Copyright (c) 2019 in FORETREE
 * D:加密 , E: 解密后的数据
 */
public interface Encrypt<D, E> {

    /**
     * 加密
     *
     * @param decrypt 需要加密的数据
     * @return
     */
    E encrypt(D decrypt);

    /**
     * 解密
     *
     * @param encrypt 加密数据
     * @return
     */
    D decrypt(E encrypt);
}
