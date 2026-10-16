/** A payment card's face image is stored as an ordinary attachment with this reserved name. */
export function isCardCoverAttachment(fileName: string): boolean {
  return /^cover\.(?:jpe?g|png|webp)$/i.test(fileName)
}
