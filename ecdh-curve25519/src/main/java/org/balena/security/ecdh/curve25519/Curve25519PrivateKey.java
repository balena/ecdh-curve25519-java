package org.balena.security.ecdh.curve25519;

import android.support.annotation.NonNull;

import java.security.PrivateKey;

public final class Curve25519PrivateKey extends Curve25519Key implements PrivateKey {
    public Curve25519PrivateKey(@NonNull byte[] key) {
        super(key);
    }
}
