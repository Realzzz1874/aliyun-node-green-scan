const GreenScanner = require('../src/index');
const sc = new GreenScanner({
  AccessKeyId: 'xxx',
  AccessKeySecret: 'xxx'
});


const start = async () => {
const a = await sc.scanText('傻逼');
  console.log(a);
}
start()