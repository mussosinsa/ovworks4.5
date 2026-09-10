package org.ovirt.engine.core.sso.utils;

/**
 * The wrapper a client puts around a credential so that a copy of the request cannot be used again
 * later.
 *
 * <p>Encrypting a credential hides what it says; it does not stop anyone who has a copy of the
 * ciphertext from sending it again. Whoever can read the request - a proxy the client trusts, a
 * capture taken on the client's own machine - holds something that logs in as that user for as long
 * as the password stands, from anywhere, as often as they like. The encryption is doing nothing
 * about that, and cannot: the server has no way to tell an encrypted credential it has just been
 * handed from the same one handed to it an hour ago.</p>
 *
 * <p>What distinguishes them is what the client puts inside the encryption alongside the
 * credential: when it was written, and a value it will never write twice.</p>
 *
 * <pre>
 * ovirt-login:v1:&lt;seconds since the epoch&gt;:&lt;nonce&gt;:&lt;credential&gt;
 * </pre>
 *
 * <p>The credential is the rest of the line, so it may contain colons. It is written last for that
 * reason.</p>
 *
 * <p>An unwrapped credential is still recognised, for clients that have not been updated - see
 * {@code LoginReplayGuard}, which decides whether those are still accepted. A credential that
 * itself begins with this prefix would be read as a wrapper by mistake; a wrapping client never
 * sends one, since it wraps whatever the user typed.</p>
 */
public final class LoginEnvelope {

    /** What marks a credential as wrapped. Change this, and the version in it, if the shape does. */
    public static final String PREFIX = "ovirt-login:v1:"; //$NON-NLS-1$

    private static final String SEPARATOR = ":"; //$NON-NLS-1$

    /** Timestamp, nonce, and the credential that makes up the rest of the line. */
    private static final int PARTS = 3;

    /** A nonce only has to be unguessable, not long; this is well past what that takes. */
    private static final int MAX_NONCE_LENGTH = 64;

    private final long issuedAtEpochSecond;
    private final String nonce;
    private final String credential;

    private LoginEnvelope(long issuedAtEpochSecond, String nonce, String credential) {
        this.issuedAtEpochSecond = issuedAtEpochSecond;
        this.nonce = nonce;
        this.credential = credential;
    }

    /** @return true when the decrypted text claims to be wrapped */
    public static boolean isWrapped(String decrypted) {
        return decrypted != null && decrypted.startsWith(PREFIX);
    }

    /**
     * Reads a wrapped credential.
     *
     * @param decrypted the decrypted text, which must be {@link #isWrapped(String) wrapped}
     * @return what the wrapper carries
     * @throws IllegalArgumentException when the text claims to be wrapped but is not readable. It
     *         is never treated as an unwrapped credential in that case: a wrapper the server cannot
     *         read is a wrapper it cannot check, and accepting it would be the way around this.
     */
    public static LoginEnvelope parse(String decrypted) {
        if (!isWrapped(decrypted)) {
            throw new IllegalArgumentException("not a wrapped credential"); //$NON-NLS-1$
        }

        String[] parts = decrypted.substring(PREFIX.length()).split(SEPARATOR, PARTS);
        if (parts.length != PARTS) {
            throw new IllegalArgumentException(
                    "a wrapped credential needs a timestamp, a nonce and the credential"); //$NON-NLS-1$
        }

        long issuedAt;
        try {
            issuedAt = Long.parseLong(parts[0].trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("the timestamp is not a number of seconds", e); //$NON-NLS-1$
        }

        String nonce = parts[1].trim();
        if (nonce.isEmpty() || nonce.length() > MAX_NONCE_LENGTH) {
            throw new IllegalArgumentException("the nonce is missing or longer than this accepts"); //$NON-NLS-1$
        }

        return new LoginEnvelope(issuedAt, nonce, parts[2]);
    }

    /** @return when the client says it wrote this, in seconds since the epoch */
    public long getIssuedAtEpochSecond() {
        return issuedAtEpochSecond;
    }

    /** @return the value the client promises never to write again */
    public String getNonce() {
        return nonce;
    }

    /** @return the credential the wrapper carries */
    public String getCredential() {
        return credential;
    }
}
