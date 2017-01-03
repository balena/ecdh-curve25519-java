package br.eti.balena.security.ecdh.curve25519;

import org.junit.Test;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import static br.eti.balena.security.ecdh.curve25519.Curve25519.ALGORITHM;
import static org.junit.Assert.assertArrayEquals;

public class KeyExchangeTest {
    @Test
    public void keyExchangeTest() throws Exception {
        Curve25519KeyPairGenerator keyPairGenerator = new Curve25519KeyPairGenerator();

        // Ana generates a key-pair as follows:
        KeyPair keyPair1 = keyPairGenerator.generateKeyPair();

        // Now Ana saves the privateKey for later, and sends the publicKey1 to Bob.

        // Bob now generates his key pair:
        KeyPair keyPair2 = keyPairGenerator.generateKeyPair();

        // Now Bob obtains the sharedSecret2 in this manner:
        Curve25519KeyAgreement keyAgreement2 = new Curve25519KeyAgreement(keyPair2.getPrivate());
        keyAgreement2.doFinal(keyPair1.getPublic());
        SecretKey sharedSecret2 = keyAgreement2.generateSecret(ALGORITHM);

        // And, by using sharedSecret1, Bob can now encrypt the message.

        // At the Ana's side, the same sharedSecret1 is generated from the
        // publicKey2 sent by Bob.
        Curve25519KeyAgreement keyAgreement1 = new Curve25519KeyAgreement(keyPair1.getPrivate());
        keyAgreement1.doFinal(keyPair2.getPublic());
        SecretKey sharedSecret1 = keyAgreement1.generateSecret(ALGORITHM);

        // Confirms that both shared secrets are equal.
        assertArrayEquals(sharedSecret1.getEncoded(),
                sharedSecret2.getEncoded());
    }
}