package br.eti.balena.security.ecdh.curve25519.spec;

import java.io.Serializable;
import java.security.spec.AlgorithmParameterSpec;

public class Curve25519ParameterSpec implements AlgorithmParameterSpec, Serializable {
    private static final long SERIAL_VERSION_UID = 42L;

    public Curve25519ParameterSpec() {
        // nothing to do.
    }

    @Override
    public int hashCode() {
        return Long.valueOf(SERIAL_VERSION_UID).hashCode();
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof Curve25519ParameterSpec))
            return false;
        return true;
    }
}
