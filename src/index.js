const uuid = require('uuid');
const axios = require('axios');
const crypto = require('crypto');

class GreenScanner {
  constructor({ AccessKeyId, AccessKeySecret, endpoint = "" }) {
    this.AccessKeyId = AccessKeyId;
    this.AccessKeySecret = AccessKeySecret;
    this.endpoint = endpoint || "green.cn-shanghai.aliyuncs.com";
    this.textPath = "/green/text/scan";
    this.clientInfo = { ip: "127.0.0.1" };
  }

  _signature(headers, path) {
    const signature = [];
    signature.push("POST\n");
    signature.push("application/json\n");
    signature.push(`${headers["Content-MD5"]}\n`);
    signature.push("application/json\n");
    signature.push(`${headers["Date"]}\n`);
    signature.push("x-acs-signature-method:HMAC-SHA1\n");
    signature.push(
      `x-acs-signature-nonce:${headers["x-acs-signature-nonce"]}\n`
    );
    signature.push("x-acs-signature-version:1.0\n");
    signature.push("x-acs-version:2018-05-09\n");
    signature.push(`${path}?clientInfo=${JSON.stringify(this.clientInfo)}`);
    const auth = crypto
      .createHmac("sha1", this.AccessKeySecret)
      .update(signature.join(""))
      .digest()
      .toString("base64");
    return `acs ${this.AccessKeyId}:${auth}`;
  }

  _generatHeaders(requestBody, path) {
    let requestHeaders = {
      Accept: "application/json",
      "Content-Type": "application/json",
      "Content-MD5": crypto
        .createHash("md5")
        .update(JSON.stringify(requestBody))
        .digest()
        .toString("base64"),
      Date: new Date().toUTCString(),
      "x-acs-version": "2018-05-09",
      "x-acs-signature-nonce": uuid.v4(),
      "x-acs-signature-version": "1.0",
      "x-acs-signature-method": "HMAC-SHA1",
      Authorization: "",
    };
    requestHeaders["Authorization"] = this._signature(requestHeaders, path);
    return requestHeaders;
  }

  async scanText(text) {
    const requestBody = {
      scenes: ['antispam'],
      tasks: [
        {
          dataId: uuid.v4(),
          content: text,
        },
      ],
    };
    const requestHeaders = this._generatHeaders(requestBody, this.textPath);

    const options = {
      method: "POST",
      url: `https://${this.endpoint}${this.textPath}`,
      data: requestBody,
      responseType: "json",
      headers: requestHeaders,
    };
    try {
      const res = await axios(options);
      if (res.status == 200) {
        return res.data;
      }
    } catch (err) {
      throw err;
    }
  }
}

module.exports = GreenScanner;
