import { execSync } from 'child_process';
import Debug from 'debug';
import { CertificateApi } from './interface';

const debug = Debug('trusted-cert:platform:darwin');

export const darwin: CertificateApi = {
  platform: 'darwin',
  async add({ path }) {
    debug('添加证书%o到系统钥匙串', path);
    execSync(`sudo security add-trusted-cert \
          -d -r trustRoot \
          -k /Library/Keychains/System.keychain \
          '${path}'`);
  },
  async remove(name) {
    try {
      debug(`sudo security delete-certificate -c "${name}"`);
      execSync(`sudo security delete-certificate -c "${name}"`);
      return true;
    } catch (e) {
      debug('删除证书失败%o', e);
      return false;
    }
  },
  async getHashList(cn) {
    debug('查询钥匙串里名称是%o的证书', cn);
    let sha1List: string[];
    try {
      // 钥匙串里没有时执行下面会抛错
      const sha1Str = execSync(
        `security find-certificate -a -c '${cn}' -Z | grep ^SHA-1`,
        { encoding: 'utf-8' }
      );
      sha1List = sha1Str
        .replace(/SHA-1\shash:\s/g, '')
        .split('\n')
        .filter((sha1) => sha1);
    } catch (e) {
      sha1List = [];
    }
    debug('查询到的sha1 %o', sha1List);
    return sha1List;
  },
};
