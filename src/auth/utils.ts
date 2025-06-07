export function randomString(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function isJwt(token: string): boolean {
  return token.split('.').length === 3;
}

export function isJwe(token: string): boolean {
  return token.split('.').length === 5;
}

export function decodeJwt(token: string): unknown | undefined {
  if (!isJwt(token)) return undefined;
  const [, payload] = token.split('.');
  const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
  const json = decodeURIComponent(
    decoded
      .split('')
      .map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
      .join(''),
  );
  return JSON.parse(json);
}
