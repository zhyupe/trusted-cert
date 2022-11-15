import { asn1, md, pki } from 'node-forge';
import isIp from 'is-ip';

export const generateKeyPair = (
  options?: pki.rsa.GenerateKeyPairOptions
): Promise<pki.rsa.KeyPair> => {
  return new Promise((resolve, reject) => {
    pki.rsa.generateKeyPair(options, (err, keypair) => {
      if (err) {
        reject(err);
      } else {
        resolve(keypair);
      }
    });
  });
};

const commonNames = {
  ca: 'generated by trusted-cert2',
  cert: 'localhost',
};

// certificate Attributes: https://git.io/fptna
const getCertAttrs = (commonName: string) => [
  {
    name: 'commonName',
    value: commonName,
  },
];

const signCert = function ({
  caPrivKey,
  caCertAttrs = getCertAttrs(commonNames.ca),
  publicKey,
  certAttrs = getCertAttrs(commonNames.cert),
  extensions = [],
  // Chrome only accept certs which validity period is less than 398 days
  // See https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/certificate_lifetimes.md
  expiresIn = 397 * 86400e3,
}: {
  caPrivKey: pki.PrivateKey;
  caCertAttrs?: Array<pki.CertificateField>;
  publicKey: pki.PublicKey;
  certAttrs?: Array<pki.CertificateField>;
  extensions?: Array<any>;
  expiresIn?: number;
}) {
  const now = new Date();
  const cert = pki.createCertificate();
  cert.publicKey = publicKey;

  // Conforming CAs should ensure serialNumber is:
  // - no more than 20 octets
  // - non-negative (prefix a '00' if your value starts with a '1' bit)
  cert.serialNumber = now.getTime().toString(16);
  if (cert.serialNumber.length % 2) {
    // Ensure serialNumber arr octets
    cert.serialNumber = '0' + cert.serialNumber;
  } else if (cert.serialNumber.charCodeAt(0) >= 0x38) {
    // Ensure serialNumber starts with 0-7 (non-negative)
    cert.serialNumber = '00' + cert.serialNumber;
  }

  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now.getTime() + expiresIn);

  cert.setSubject(certAttrs);
  cert.setIssuer(caCertAttrs);

  cert.setExtensions(extensions);
  cert.sign(caPrivKey, md.sha256.create());

  return cert;
};

export const createCACert = (keys: pki.KeyPair) =>
  signCert({
    caPrivKey: keys.privateKey,
    publicKey: keys.publicKey,
    certAttrs: getCertAttrs(commonNames.ca),
    extensions: [
      {
        name: 'basicConstraints',
        cA: true,
      },
    ],
    // 10 years
    expiresIn: 3650 * 86400e3,
  });

export function createCert({
  caPrivKey,
  caCertAttrs,
  publicKey,
  hosts,
  expiresIn,
}: {
  caPrivKey: pki.PrivateKey;
  caCertAttrs?: Array<pki.CertificateField>;
  publicKey: pki.PublicKey;
  hosts: string[];
  expiresIn?: number;
}) {
  const domainIndex = hosts.findIndex((host) => !isIp(host));
  const cn = domainIndex === -1 ? 'localhost' : hosts[domainIndex];
  const attributes = [{ name: 'commonName', value: cn }];

  // required certificate extensions for a certificate authority
  const extensions: any[] = [
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
      nonRepudiation: true,
    },
    { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
  ];

  const types = { domain: 2, ip: 7 }; // available Types: https://git.io/fptng
  const altNames: any[] = [];
  hosts.forEach((host, i) => {
    if (i === domainIndex) return;

    if (isIp(host)) {
      altNames.push({ type: types.ip, ip: host });
    } else {
      altNames.push({ type: types.domain, value: host });
    }
  });

  if (altNames.length) {
    extensions.push({
      name: 'subjectAltName',
      altNames,
    });
  }

  return signCert({
    caPrivKey,
    caCertAttrs,
    certAttrs: attributes,
    publicKey,
    extensions,
    expiresIn,
  });
}

/**
 * 获取证书里支持的域名
 */
export const getCertHosts = (cert: pki.Certificate): string[] => {
  const result: string[] = [getCertCommonName(cert)];
  const subjectAltName = cert.getExtension('subjectAltName') as
    | {
        altNames: Array<{
          type: 2 | 7;
          value: string;
          ip: string;
        }>;
      }
    | undefined;
  if (subjectAltName?.altNames) {
    subjectAltName.altNames.forEach((host) => {
      if (host.type === 2) {
        result.push(host.value);
      } else if (host.type === 7) {
        result.push(host.ip);
      }
    });
  }
  return result;
};

/**
 * 获取缓存的证书文件里的sha1值
 */
export const getCertSha1 = (cert: pki.Certificate): string => {
  const bytes = asn1.toDer(pki.certificateToAsn1(cert)).getBytes();
  return md.sha1.create().update(bytes).digest().toHex().toUpperCase();
};

/**
 * 获取证书的有效时间
 */
export const getCertValidPeriod = (cert: pki.Certificate): string => {
  return `${cert.validity.notBefore} ~ ${cert.validity.notAfter}`;
};

/**
 * 获取证书的名称
 */
export const getCertCommonName = (cert: pki.Certificate): string => {
  const cn: pki.Attribute = cert.subject.getField({ name: 'commonName' });
  if (!cn) {
    throw new Error('Failed reading commonName of cert');
  }

  return cn.value;
};

export const isCertSignedByCA = (
  cert: pki.Certificate,
  ca: pki.Certificate
) => {
  return ca.verify(cert);
};
