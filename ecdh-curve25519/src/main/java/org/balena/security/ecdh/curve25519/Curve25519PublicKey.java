package com.twigo.app.purchase.djb;

import android.support.annotation.NonNull;

import java.security.PublicKey;

public class Curve25519PublicKey implements PublicKey {
    private byte[] mKey;

    public Curve25519PublicKey(@NonNull byte[] key) {
        mKey = key;
    }

    @Override
    public String getAlgorithm() {
        return Curve25519Provider.ALGORITHM;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return mKey;
    }
}
