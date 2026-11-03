/**
 * The set of stable error codes this package raises.
 *
 * Branch on `err.code`, not on `err.message`: the codes are part of the
 * public API, the prose is not.
 */
export type HpkeErrorCode =
    'ERR_INVALID_RECIPIENT_KEY'|
    'ERR_INVALID_KEYPAIR'|
    'ERR_SMALL_ORDER_KEY'|
    'ERR_MALFORMED_ENVELOPE'|
    'ERR_MALFORMED_MESSAGE'|
    'ERR_INVALID_KEYSIZE'|
    'ERR_INVALID_AES_KEY'|
    'ERR_DECRYPT_FAILED'

/**
 * An `Error` carrying a stable `code`. Every throw site in this package
 * raises one of these, so callers can branch on the failure instead of
 * pattern matching on a message.
 *
 * Where a WebCrypto failure is being wrapped, the original is kept on
 * `cause`.
 */
export class HpkeError extends Error {
    readonly code:HpkeErrorCode

    constructor (
        code:HpkeErrorCode,
        message:string,
        opts?:{ cause?:unknown }
    ) {
        super(message, opts)
        this.name = 'HpkeError'
        this.code = code
    }
}
