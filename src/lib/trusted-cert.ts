import { readFileSync, writeFileSync } from 'fs-extra';
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
} from './cert';
import Debug from 'debug';
import { addToKeyChain, getKeyChainCertSha1List } from '../platform';
import applicationConfigPath from './application-config-path';
import { I18nDict } from '../i18n/interface';
import { mergeI18n } from '../i18n';
import { getAdded, isMatched } from './util';

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

interface CertAndKey {
  cert: pki.Certificate;
  key: pki.rsa.PrivateKey;
}

export class TrustedCert {
  private dir: string;
  private caName: string;
  private sslName: string;

  private i18n: I18nDict;

  constructor({
    dir = applicationConfigPath('trusted-cert'),
    caName = 'ca',
    sslName = 'ssl',
    i18n = {},
  }: {
    dir?: string;
    caName?: string;
    sslName?: string;
    i18n?: Partial<I18nDict>;
  } = {}) {
    this.dir = dir;
    this.caName = caName;
    this.sslName = sslName;

    this.i18n = mergeI18n(i18n);
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

  async sign({
    ca,
    hosts,
    overwrite = false,
  }: {
    ca?: CertAndKey;
    hosts: string[];
    overwrite?: boolean;
  }) {
    if (!ca) {
      ca = await this.ensureCA();
    }

    let ssl = this.loadCert();
    let signHosts = [...hosts];
    if (!overwrite && ssl) {
      const currentHosts = getCertHosts(ssl.cert);
      if (isMatched(currentHosts, hosts)) {
        console.log('现有证书已经满足需求');
        return;
      }

      const addHosts = getAdded(currentHosts, signHosts);
      signHosts = [...currentHosts, ...addHosts];
    }

    let privateKey = ssl?.key;
    let publicKey: pki.PublicKey;
    if (privateKey) {
      publicKey = pki.rsa.setPublicKey(privateKey.n, privateKey.e);
    } else {
      const keypair = await this.generateKeyPair();
      writeKey(this.dir, this.sslName, keypair.privateKey);

      privateKey = keypair.privateKey;
      publicKey = keypair.publicKey;
    }

    const cert = createCert({
      caPrivKey: ca.key,
      caCertAttrs: ca.cert.subject.attributes,
      publicKey,
      hosts: Array.from(signHosts),
    });

    writeCert(this.dir, this.sslName, cert);

    return {
      key: pki.privateKeyToPem(privateKey),
      cert: pki.certificateToPem(cert),
      keyFilePath: keyPath(this.dir, this.sslName),
      certFilePath: certPath(this.dir, this.sslName),
    };
  }

  async trust(ca: CertAndKey) {
    let trusted = false;
    if (!this.isCertTrusted(ca.cert)) {
      console.log('正在将 CA 证书写入系统信任区');
      try {
        addToKeyChain(certPath(this.dir, this.caName));
        trusted = true;
      } catch (e) {
        console.warn('CA 写入失败');
        trusted = false;
      }
    }

    return trusted;
  }

  async info() {
    const ssl = this.loadCert();
    if (!ssl) {
      return this.printNoInstall();
    }

    const validity = getCertValidPeriod(ssl.cert);
    const crtHosts = getCertHosts(ssl.cert);

    console.log(
      this.i18n.info_ssl_key_path ?? '密钥文件路径：',
      keyPath(this.dir, this.sslName)
    );
    console.log(
      this.i18n.info_ssl_cert_path ?? '自签名证书文件路径：',
      certPath(this.dir, this.sslName)
    );
    console.log(
      this.i18n.info_ssl_cert_support_hosts ?? '自签名证书已经支持的域名：',
      crtHosts.join(',')
    );
    console.log(
      this.i18n.info_ssl_cert_valid_period ?? '自签名证书的有效时间：',
      validity
    );

    this.caInfo();
  }

  async caInfo() {
    const ca = await this.ensureCA();

    if (this.isCertTrusted(ca.cert)) {
      const sha1 = getCertSha1(ca.cert);
      const validity = getCertValidPeriod(ca.cert);
      const cn = getCertCommonName(ca.cert);

      console.log(
        this.i18n.info_ssl_cert_trusted_desc ??
          '自签名证书已经添加到钥匙串并被始终信任'
      );
      console.log(
        this.i18n.info_keychains_cert_name ?? '自签名证书在钥匙串里的名称：',
        cn,
        ', ',
        this.i18n.info_keychains_cert_sha1 ?? '自签名证书在钥匙串里的sha-1：',
        sha1
      );
      console.log(
        this.i18n.info_ssl_cert_valid_period ?? '自签名证书的有效时间：',
        validity
      );
    } else {
      console.log(
        this.i18n.info_ssl_cert_not_trusted ??
          '自签名证书还没被添加到钥匙串，可以运行下面命令，执行添加和始终信任'
      );
      console.log(
        this.i18n.info_ssl_cert_trusted_cli_tip ?? '$ trusted-cert trust'
      );
    }
  }

  /**
   * 判断没安装过证书给提示
   */
  private async printNoInstall() {
    console.warn(this.i18n.host_add_no_install);
    console.warn(this.i18n.host_add_no_install_operation_tip);
  }

  private generateKeyPair() {
    return generateKeyPair({ bits: 2048, workers: 4 });
  }

  private loadCert(): CertAndKey | null {
    try {
      const cert = readCert(this.dir, this.sslName);
      const key = readKey(this.dir, this.sslName);

      return { cert, key };
    } catch (e: any) {
      if (e.code !== 'ENOENT') {
        throw e;
      }

      return null;
    }
  }

  private async ensureCA() {
    let cert: pki.Certificate;
    let key: pki.PrivateKey;

    try {
      cert = readCert(this.dir, this.caName);
      key = readKey(this.dir, this.caName);
    } catch (e: any) {
      if (e.code !== 'ENOENT') {
        throw e;
      }

      try {
        const keyPair = await this.generateKeyPair();

        cert = createCACert(keyPair);
        key = keyPair.privateKey;

        writeCert(this.dir, this.caName, cert);
        writeKey(this.dir, this.caName, key);
      } catch (e) {
        throw new Error('Failed creating CA cert');
      }
    }

    return { cert, key };
  }

  private isCertTrusted(cert: pki.Certificate) {
    const cn = getCertCommonName(cert);

    const list = getKeyChainCertSha1List(cn);
    const sha1 = getCertSha1(cert);
    debug(`已经添加信任的证书sha1${list.join(',')}`);
    debug(`证书文件的sha1${sha1}`);

    return list.includes(sha1);
  }
}
