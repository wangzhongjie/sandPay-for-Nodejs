const crypto = require('crypto');
const path = require('path');
const fs = require('fs');


var sdpay = {
    /**
     * 从文件加载公钥和私钥
     * key实际上就是PEM编码的字符串
     * @param {string} file 文件路径
     * @return string
     */
    loadKey: function(file) {
        file = path.join(__dirname, file)
        return fs.readFileSync(file, 'utf8');
    },


    /**
     * 生成随机的AESKey
     * 8的倍数，默认16个128位
     * @param {number} size
     * @return string
     */
    aes_generate: function(size) {
        const str = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let arr = []
        for (let i = 0; i < size; i++) {
            arr.push(str[rnd(0, 61)])
        }
        return arr.join('')
    },

    /**
     * 公钥加密AESKey
     * @param {string} plainAESKey 明文aeskey
     * @param {string} pubKey 明文公钥
     * @return {string} base64密文aeskey
     */
    RSAEncryptByPub: function(plainAESKey, pubKey) {
        plainAESKey = Buffer.from(plainAESKey, 'utf8')
        pubKey = Buffer.from(pubKey, 'utf8')
        try {
            let encryptKey = crypto.publicEncrypt({ key: pubKey, padding: crypto.constants.RSA_PKCS1_PADDING }, plainAESKey);
            return encryptKey.toString('base64');
        } catch (e) {
            throw new Error('公钥加密AESKey错误：' + e)
        }
    },

    /**
     * 私钥解密AESKey
     * @param {string} cipherAESKey base64密文aeskey
     * @param {string} priKey 明文私钥
     * @return {string} 明文aeskey
     */
    RSADecryptByPri: function(cipherAESKey, priKey) {
        cipherAESKey = Buffer.from(cipherAESKey, 'base64')
        priKey = Buffer.from(priKey, 'utf8')

        try {
            let decryptAESKey = crypto.privateDecrypt({ key: priKey, padding: crypto.constants.RSA_PKCS1_PADDING }, cipherAESKey);
            return decryptAESKey
        } catch (e) {
            throw new Error('私钥解密AESKey错误：' + e)
        }
    },




    /**
     * AES加密
     * @param {string} data 明文报文
     * @param {string} AESkey 明文AESkey
     * @param {string} algorithm 算法
     * @param {null} iv 随机偏移量
     * @return {string} base64 加密报文
     */
    AESEncrypt: function(data, AESkey, algorithm, iv) {
        const cipherEncoding = 'base64';
        const clearEncoding = 'utf8';
        try {
            var cipher = crypto.createCipheriv(algorithm, AESkey, iv);
            return cipher.update(data, clearEncoding, cipherEncoding) + cipher.final(cipherEncoding);
        } catch (e) {
            throw new Error('aes加密错误：' + e)
        }
    },

    /**
     * AES解密
     * @param {string} data base64 加密报文
     * @param {string} AESkey 明文AESkey
     * @param {string} algorithm 算法
     * @param {null} iv 随机偏移量
     * @returns {string}  明文报文
     */
    AESDecrypt: function(data, AESkey, algorithm, iv) {
        const cipherEncoding = 'base64';
        const clearEncoding = 'utf8';
        try {
            var cipher = crypto.createDecipheriv(algorithm, AESkey, iv);
            return cipher.update(data, cipherEncoding, clearEncoding) + cipher.final(clearEncoding);
        } catch (e) {
            throw new Error('aes解密错误：' + e)
        }
    },

    /**
     * 私钥签名
     * @param {string} plainText 明文报文 
     * @param {string} priKey 私钥 
     * @param {string} signAlgorithm 签名算法 
     * @return {string} 已签名base64密文
     */
    sign: function(plainText, priKey, signAlgorithm) {
        plainText = JSON.stringify(plainText)
        priKey = Buffer.from(priKey, 'utf8')
        try {
            const sign = crypto.createSign(signAlgorithm);
            sign.write(plainText);
            sign.end();

            const sign_b64 = sign.sign(priKey, 'base64');
            return sign_b64
        } catch (e) {
            throw new Error('私钥签名错误：' + e)
        }
    },

    /**
     * 公钥验签
     * @param {string} plainText  解密后的明文报文
     * @param {string} sign 签名 
     * @param {string} pubKey 公钥
     * @param {string} signAlgorithm 验签算法
     * @return {boolean} 
     */
    verify: function(plainText, sign, pubKey, signAlgorithm) {
        sign = Buffer.from(sign, 'base64')
        pubKey = Buffer.from(pubKey, 'utf8')

        try {
            const verify = crypto.createVerify(signAlgorithm);
            verify.write(plainText);
            verify.end();

            var isOk = verify.verify(pubKey, sign, 'base64');

            if (!isOk) {
                throw new Error('验签失败')
            }
            return true
        } catch (e) {
            throw new Error('公钥验签错误：' + e)
        }
    }
}

function rnd(m, n) {
    return parseInt(Math.random() * (m - n) + n)
}


module.exports = sdpay;