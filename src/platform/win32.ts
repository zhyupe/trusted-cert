import { exec, execSync } from 'child_process';
import Debug from 'debug';
import { CertificateApi } from './interface';

const debug = Debug('trusted-cert:platform:win32');

export const win32: CertificateApi = {
  platform: 'win32',
  async add({ path }) {
    exec(`certutil -addstore -user root ${path}`);
  },
  async remove(name) {
    try {
      execSync(`certutil -delstore -user root "${name}"`);
      return true;
    } catch (e) {
      debug('删除证书失败%o', e);
      return false;
    }
  },
  async getHashList(cn) {
    try {
      // 钥匙串里没有时执行下面会抛错
      const sha1Str = execSync(
        `certutil -verifystore -user root "${cn}" | findstr sha1`,
        { encoding: 'utf8' }
      );

      return sha1Str
        .split('\n')
        .map((item) => {
          return item
            .replace(/.*\(sha1\):\s/, '')
            .replace(/[\s\r]/g, '')
            .toUpperCase();
        })
        .filter(Boolean);
    } catch (e) {
      debug('获取钥匙串里证书失败%o', e);
      return [];
    }
  },
};
