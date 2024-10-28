import { ensureDirSync, readFileSync, rm, writeFileSync } from 'fs-extra';
import { pki } from 'node-forge';
import { join } from 'path';
import {
  createCACert,
  createCert,
  generateKeyPair,
  getCertCommonName,
  getCertHosts,
  getCertSha1,
  getCertValidPeriod,
  isCertSignedByCA,
  isCertValid,
} from './cert';
import Debug from 'debug';
import applicationConfigPath from './application-config-path';
import { I18nDict, I18nDictModifier } from '../i18n/interface';
import { mergeI18n } from '../i18n';
import { getAdded, isMatched } from './util';
import { format } from 'util';
import { CertificateApi } from '../platform/interface';
import { getCertificateApi } from '../platform';

const debug = Debug('trusted-cert:class');

const certPath = (dir: string, name: string) => join(dir, `${name}.crt`);
const keyPath = (dir: string, name: string) => join(dir, `${name}.key`);

const readCert = (dir: string, name: string) => {
  return pki.certificateFromPem(readFileSync(certPath(dir, name), 'utf-8'));
};

const readKey = (dir: string, name: string) => {
  return pki.privateKeyFromPem(readFileSync(keyPath(dir, name), 'utf-8'));
};

const writeCert = (dir: string, name: string, content: pki.Certificate) => {
  writeFileSync(certPath(dir, name), pki.certificateToPem(content));
};

const writeKey = (dir: string, name: string, content: pki.PrivateKey) => {
  writeFileSync(keyPath(dir, name), pki.privateKeyToPem(content));
};

const rmAll = (files: string[]) =>
  Promise.all(files.map((file) => rm(file).catch(() => {})));

interface CertAndKey {
  cert: pki.Certificate;
  key: pki.rsa.PrivateKey;
}

export class TrustedCert {
  private dir: string;
  private caName: string;
  private sslName: string;
  private quiet: boolean;

  private i18n: I18nDict;
  private api: CertificateApi;

  constructor({
    dir = applicationConfigPath('trusted-cert'),
    caName = 'ca',
    sslName = 'ssl',
    quiet = false,
    i18n = {},
  }: {
    dir?: string;
    caName?: string;
    sslName?: string;
    quiet?: boolean;
    i18n?: I18nDictModifier;
  } = {}) {
    this.dir = dir;
    this.caName = caName;
    this.sslName = sslName;
    this.quiet = quiet;

    this.i18n = mergeI18n(i18n);
    this.api = getCertificateApi();
  }

  async install({
    hosts,
    overwrite = false,
  }: {
    hosts: string[];
    overwrite?: boolean;
  }) {
    const ca = await this.ensureCA();
    const trusted = await this.trust(ca);

    const certInfo = await this.sign({
      ca,
      hosts,
      overwrite,
    });

    return {
      ...certInfo,
      trusted,
    };
  }

  async uninstall() {
    const ca = this.loadCA();
    if (ca) {
      if (await this.isCertTrusted(ca.cert)) {
        const cn = getCertCommonName(ca.cert);
        this.log(this.l('uninstall_del_keychain', cn));

        try {
          await this.api.remove(cn);
          this.log(this.l('uninstall_del_keychain_success'));
        } catch (e: any) {
          console.error(this.l('uninstall_del_keychain_failure', e.message));
          return false;
        }
      }

      await rmAll([
        certPath(this.dir, this.caName),
        keyPath(this.dir, this.caName),
      ]);
    }

    await rmAll([
      certPath(this.dir, this.sslName),
      keyPath(this.dir, this.sslName),
    ]);

    this.log(this.l('uninstall_complete'));
  }

  async sign({
    ca,
    sslName,
    expiresIn,
    hosts,
    overwrite = false,
  }: {
    ca?: CertAndKey;
    sslName?: string;
    expiresIn?: number;
    hosts: string[];
    overwrite?: boolean;
  }) {
    if (!ca) {
      ca = await this.ensureCA();
    }

    if (!sslName) {
      sslName = this.sslName;
    }

    ensureDirSync(this.dir);

    let ssl = this.loadSSL();
    let signHosts = [...hosts];
    if (!overwrite && ssl) {
      let valid = true;
      if (!isCertSignedByCA(ssl.cert, ca.cert)) {
        this.log(this.l('sign_ca_mismatch'));
        valid = false;
      }

      if (!isCertValid(ssl.cert)) {
        this.log(this.l('sign_cert_expired'));
        valid = false;
      }

      const currentHosts = getCertHosts(ssl.cert);
      if (valid && isMatched(currentHosts, hosts)) {
        this.log(this.l('sign_cert_satisfied'));
        return {
          key: pki.privateKeyToPem(ssl.key),
          cert: pki.certificateToPem(ssl.cert),
          keyFilePath: keyPath(this.dir, sslName),
          certFilePath: certPath(this.dir, sslName),
        };
      }

      const addHosts = getAdded(currentHosts, signHosts);
      signHosts = [...currentHosts, ...addHosts];
    }

    if (signHosts.length === 0) {
      throw new Error(this.l('sign_host_empty'));
    }

    let privateKey = ssl?.key;
    let publicKey: pki.PublicKey;
    if (privateKey) {
      publicKey = pki.rsa.setPublicKey(privateKey.n, privateKey.e);
    } else {
      const keypair = await this.generateKeyPair();
      writeKey(this.dir, sslName, keypair.privateKey);

      privateKey = keypair.privateKey;
      publicKey = keypair.publicKey;
    }

    const cert = createCert({
      caPrivKey: ca.key,
      caCertAttrs: ca.cert.subject.attributes,
      publicKey,
      expiresIn,
      hosts: Array.from(signHosts),
    });

    writeCert(this.dir, sslName, cert);
    this.log(this.l('sign_complete'));

    return {
      key: pki.privateKeyToPem(privateKey),
      cert: pki.certificateToPem(cert),
      keyFilePath: keyPath(this.dir, sslName),
      certFilePath: certPath(this.dir, sslName),
    };
  }

  async doTrust() {
    const ca = await this.ensureCA();
    return this.trust(ca);
  }

  info() {
    const ssl = this.loadSSL();
    if (!ssl) {
      this.log(this.l('info_no_install'));
      return;
    }

    const validity = getCertValidPeriod(ssl.cert);
    const crtHosts = getCertHosts(ssl.cert);

    this.log(this.l('info_ssl_key_path', keyPath(this.dir, this.sslName)));
    this.log(this.l('info_ssl_cert_path', certPath(this.dir, this.sslName)));
    this.log(this.l('info_ssl_cert_valid_period', validity));
    this.log(this.l('info_ssl_cert_support_hosts', crtHosts.join(', ')));
  }

  async caInfo() {
    const ca = this.loadCA();
    if (!ca) {
      this.log(this.l('ca_not_created'));
      return;
    }

    const sha1 = getCertSha1(ca.cert);
    const validity = getCertValidPeriod(ca.cert);
    const cn = getCertCommonName(ca.cert);

    this.log(this.l('ca_info_name', cn));
    this.log(this.l('ca_info_fingerprint', sha1));
    this.log(this.l('ca_info_valid_period', validity));

    this.log('');

    if (await this.isCertTrusted(ca.cert)) {
      this.log(this.l('ca_info_trusted'));
    } else {
      this.log(this.l('ca_info_not_trusted'));
    }
  }

  private async trust(ca: CertAndKey) {
    let trusted = false;
    if (!this.isCertTrusted(ca.cert)) {
      this.log(this.l('add_trust_process'));
      try {
        await this.api.add({
          name: this.caName,
          path: certPath(this.dir, this.caName),
        });
        trusted = true;
        this.log(this.l('add_trust_succeed'));
      } catch (e: any) {
        console.warn(this.l('add_trust_failed', e.message));
        trusted = false;
      }
    }

    return trusted;
  }

  private generateKeyPair() {
    return generateKeyPair({ bits: 2048, workers: 4 });
  }

  private loadCertAndKey(name: string): CertAndKey | null {
    try {
      const cert = readCert(this.dir, name);
      const key = readKey(this.dir, name);

      return { cert, key };
    } catch (e: any) {
      if (e.code !== 'ENOENT') {
        throw e;
      }

      return null;
    }
  }

  private loadSSL(): CertAndKey | null {
    return this.loadCertAndKey(this.sslName);
  }

  private loadCA(): CertAndKey | null {
    return this.loadCertAndKey(this.caName);
  }

  private async ensureCA(): Promise<CertAndKey> {
    const ca = this.loadCA();
    if (ca) {
      return ca;
    }

    let cert: pki.Certificate;
    let key: pki.PrivateKey;

    try {
      const keyPair = await this.generateKeyPair();

      cert = createCACert(keyPair);
      key = keyPair.privateKey;

      ensureDirSync(this.dir);
      writeCert(this.dir, this.caName, cert);
      writeKey(this.dir, this.caName, key);
    } catch (e: any) {
      throw new Error(this.l('ca_create_failed', e.message));
    }

    return { cert, key };
  }

  private async isCertTrusted(cert: pki.Certificate) {
    if (!isCertValid(cert)) {
      return false;
    }

    const cn = getCertCommonName(cert);

    const list = await this.api.getHashList(cn);
    const sha1 = getCertSha1(cert);
    debug(`已经添加信任的证书sha1 ${list.join(',')}`);
    debug(`证书文件的sha1 ${sha1}`);

    return list.includes(sha1);
  }

  private l(key: keyof I18nDict, ...args: any[]) {
    const content = this.i18n[key];
    if (args.length) {
      return format(content, ...args);
    }

    return content;
  }

  private log(message: string) {
    if (this.quiet) return;
    console.log(message);
  }
}
