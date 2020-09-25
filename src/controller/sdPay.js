const Base = require('./base.js')
const moment = require('moment')
const axios = require('axios')
const qs = require('qs')
const querystring = require('querystring')
const utils = require('./sdUtils')

const API_HOST = 'https://caspay.sandpay.com.cn/agent-main/openapi' //杉德代付接口
const PUB_KEY_PATH = 'xxxxxx' //公钥文件路径
const PRI_KEY_PATH = 'xxxxxx' //私钥文件路径

module.exports = class extends Base {

    constructor(ctx) {
        super(ctx)
    }

    // 实现代付转账
    async toPayAction() {
        const params = {
            path: '/agentpay',
            transCode: 'RTPM', // 实时代付
            merId: think.config('sdPay').merId, // 商户号
        }

        const tranTime = moment().format('YYYYMMDDHHmmss')
        const orderCode = tranTime + this.rnd(10000, 99999)
        const pt = {
            'version': '01', // 版本号
            'productId': '00000004', // 产品ID
            'tranTime': tranTime, // 交易时间
            'orderCode': orderCode, // 订单号
            'tranAmt': '000000000100', // 金额
            'currencyCode': '156', // 币种
            'accAttr': '0', // 账户属性 0对公 1对私
            'accType': '4', // 账号类型 3公司帐户 4银行卡
            'accNo': '1234567890', // 收款人帐户 号
            'accName': '全渠道', // 收款人帐户名
            'remark': 'pay', // 摘要
            // 'timeOut': '20200910200000', // 订单超时时间
            // 'bankName': 'cbc', // 收款账户开户行名称
            // 'payMode': '1', // 付款模式
            // 'channerType': '07' // 渠道类型
        }

        this.forThird(pt, params)
    }

    //监听支付成功或失败的回调
    async callbackAction() {

    }

    //查询订单
    async queryOrderAction() {

    }

    /**
     * 第三方交换数据
     * @param {Object} pt 报文
     * @param {Object} params 参数
     * @return null
     */
    async forThird(pt, params) {
        const pubKey = utils.loadKey(PUB_KEY_PATH);
        const priKeyOrgin = utils.loadKey(PRI_KEY_PATH)
        let priKey = priKeyOrgin.split('-----BEGIN PRIVATE KEY-----')[1]
        priKey = '-----BEGIN PRIVATE KEY-----' + priKey


        // step1: 生成AESKey
        const AESKey = utils.aes_generate(16);

        // step2: 使用公钥加密AESKey
        const encryptKey = utils.RSAEncryptByPub(AESKey, pubKey)

        // step3: 使用AESKey加密报文
        const encryptData = utils.AESEncrypt(JSON.stringify(pt), AESKey, 'AES-128-ECB', null);

        // step4: 使用私钥签名报文
        const sign = utils.sign(pt, priKey, 'RSA-SHA1');

        // step5: 拼接post数据
        const body = {
            'transCode': params.transCode, // 交易码
            'accessType': '0', // 接入类型 0商户接入
            'merId': params.merId, // 合作商户ID
            'encryptKey': encryptKey, // 加密后的AES秘钥
            'encryptData': encryptData, // 加密后的请求/应答报文
            'sign': sign // 签名
        };
        // console.log('bw:', body)

        // step6: post请求
        const url = API_HOST + params.path
        const response = await axios({
            'url': url,
            'method': 'post',
            'headers': { 'Content-Type': 'application/x-www-form-urlencoded' },
            'data': qs.stringify(body)
        })
        const responseData = querystring.parse(response.data)
        // console.log('res:', responseData)

        // step7: 使用私钥解密AESKey
        const decryptAESKey = utils.RSADecryptByPri(responseData['encryptKey'], priKey)
        // console.log('7 使用私钥解密AESKey: ' + decryptAESKey);

        // step8: 使用解密后的AESKey解密报文
        const decryptPlainText = utils.AESDecrypt(responseData['encryptData'], decryptAESKey, 'AES-128-ECB', null)
        console.log('8 使用解密后的AESKey解密报文', decryptPlainText)

        // step9: 使用公钥验签报文
        const plainText = utils.verify(decryptPlainText, responseData['sign'], pubKey, 'RSA-SHA1')
        console.log('9 使用公钥验签报文', plainText)

    }
}