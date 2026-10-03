import { randomBytes, createHash, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
const derive = promisify(scrypt);
export const token = () => randomBytes(32).toString('hex');
export const digest = value => createHash('sha256').update(value).digest('hex');
export async function hashPassword(password) {
  const salt = randomBytes(16).toString('hex');
  const key = await derive(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt:${salt}:${key.toString('hex')}`;
}
export async function verifyPassword(password, encoded) {
  if (!encoded || typeof password !== 'string') return false;
  const [kind, salt, hex] = encoded.split(':');
  if (kind !== 'scrypt' || !salt || hex?.length !== 128) return false;
  const key = await derive(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return timingSafeEqual(key, Buffer.from(hex, 'hex'));
}
export function fail(message, status = 400) { throw Object.assign(new Error(message), { status }); }
export function text(value, label, max = 200, required = false) {
  if (value === undefined || value === null) value = '';
  if (typeof value !== 'string') fail(`${label}格式不正确`);
  value = value.trim();
  if (value.length > max || (required && !value)) fail(`${label}${required && !value ? '不能为空' : '过长'}`);
  return value;
}
export function email(value, required = false) {
  value = text(value, '邮箱', 254, required).toLowerCase();
  if (value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) fail('请输入正确的邮箱地址');
  return value;
}
export function password(value) {
  if (typeof value !== 'string' || value.length < 10 || value.length > 128) fail('密码需为 10 至 128 个字符');
  return value;
}
export function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').filter(v => v.includes('=')).map(v => {
    const i = v.indexOf('='); return [v.slice(0, i).trim(), v.slice(i + 1)];
  }));
}
