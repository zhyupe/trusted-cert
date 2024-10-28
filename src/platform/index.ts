import { CertificateApi } from './interface';
import { darwin } from './darwin';
import { win32 } from './win32';
import { linux } from './linux';

const providers: CertificateApi[] = [darwin, win32, linux];
export function getCertificateApi(): CertificateApi {
  const api = providers.find(
    (provider) => provider.platform === process.platform
  );
  if (!api) {
    throw new Error(`未找到适配当前平台的证书管理api`);
  }

  return api;
}
