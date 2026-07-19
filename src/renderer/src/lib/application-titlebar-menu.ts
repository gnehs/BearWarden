export function shouldUseApplicationTitlebarMenu(userAgent: string): boolean {
  return !userAgent.includes('Mac')
}
