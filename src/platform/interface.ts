export interface AddCertParams {
  name: string;
  path: string;
}

export interface CertificateApi {
  platform: string;

  add: (params: AddCertParams) => Promise<void>;
  remove: (cn: string) => Promise<boolean>;
  getHashList: (cn: string) => Promise<string[]>;
}
