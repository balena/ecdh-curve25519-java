package org.balena.security.ecdh.curve25519;

import android.support.annotation.NonNull;

import java.security.PublicKey;

public final class Curve25519PublicKey extends Curve25519Key implements PublicKey {
    public Curve25519PublicKey(@NonNull byte[] key) {
        super(key);
    }
}
