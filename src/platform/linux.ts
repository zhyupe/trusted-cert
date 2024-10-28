import { execSync } from 'child_process';
import { join } from 'path';
import Debug from 'debug';
import { CertificateApi } from './interface';
import { readdir, readFile } from 'fs-extra';
import { pki } from 'node-forge';
import { getCertCommonName, getCertSha1 } from '../lib/cert';

const debug = Debug('trusted-cert:platform:linux');
const dir = '/usr/local/share/ca-certificates';
const certPath = (name: string) => join(dir, `${name}.crt`);

async function* readCerts() {
  const files = await readdir(dir);

  for (const file of files) {
    if (file.endsWith('.crt')) {
      const path = join(dir, file);
      const text = await readFile(path, 'utf-8');
      const cert = pki.certificateFromPem(text);
      yield { path, cert };
    }
  }
}

export const linux: CertificateApi = {
  platform: 'linux',
  async add({ path, name }) {
    execSync(`sudo cp ${path} ${certPath(name)}`);
    execSync('sudo update-ca-certificates');
  },
  async remove(cn) {
    try {
      for await (const { path, cert } of readCerts()) {
        if (cn === getCertCommonName(cert)) {
          execSync(`sudo rm ${path}`);
        }
      }
      execSync('sudo update-ca-certificates');
      return true;
    } catch (e) {
      debug('删除证书失败%o', e);
      return false;
    }
  },
  async getHashList(cn) {
    const result: string[] = [];

    for await (const { cert } of readCerts()) {
      if (cn === getCertCommonName(cert)) {
        result.push(getCertSha1(cert));
      }
    }

    return result;
  },
};
