package com.twigo.app.purchase.djb;

import android.support.annotation.NonNull;

import javax.crypto.SecretKey;

public class Curve25519SecretKey implements SecretKey {
    private byte[] mKey;

    public Curve25519SecretKey(@NonNull byte[] key) {
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
