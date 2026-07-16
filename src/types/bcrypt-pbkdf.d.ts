declare module 'bcrypt-pbkdf' {
  export function pbkdf(
    password: Uint8Array,
    passwordLength: number,
    salt: Uint8Array,
    saltLength: number,
    output: Uint8Array,
    outputLength: number,
    rounds: number
  ): number
}
