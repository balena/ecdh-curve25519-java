# ecdh-curve25519-java

This is a custom Diffie-Hellman key pair generator and a key agreement for the Curve25519 algorithm from Dan Bernstein, implemented as a Java Cryptography Extension (JCE). The Java version of the Curve25519 algorithm used in this implementation is a fork of https://github.com/trevorbernard/curve25519-java.git, and the algorithms can be accessed directly without access to the JCE registration, as it requires strict signatures and permissions to do so.

## Usage

```java
import org.balena.security.ecdh.curve25519.spi.Curve25519Provider;
import org.junit.Test;

import java.security.KeyPair;
import javax.crypto.SecretKey;

import static org.junit.Assert.assertArrayEquals;

public class KeyExchangeTest {
    @Test
    public void keyExchangeTest() throws Exception {
        KeyPairGenerator keyPairGenerator = new KeyPairGenerator();

        // Ana generates a key-pair as follows:
        KeyPair keyPair1 = keyPairGenerator.generateKeyPair();

        // Now Ana saves the privateKey for later, and sends the publicKey1 to Bob.

        // Bob now generates his key pair:
        KeyPair keyPair2 = keyPairGenerator.generateKeyPair();

        // Now Bob obtains the sharedSecret2 in this manner:
        KeyAgreement keyAgreement2 = new KeyAgreement(keyPair2.getPrivate());
        keyAgreement2.doFinal(keyPair1.getPublic());
        SecretKey sharedSecret2 = keyAgreement2.generateSecret(
                Curve25519Provider.ALGORITHM);

        // And, by using sharedSecret1, Bob can now encrypt the message.

        // At the Ana's side, the same sharedSecret1 is generated from the
        // publicKey2 sent by Bob.
        KeyAgreement keyAgreement1 = new KeyAgreement(keyPair1.getPrivate());
        keyAgreement1.doFinal(keyPair2.getPublic());
        SecretKey sharedSecret1 = keyAgreement1.generateSecret(
                Curve25519Provider.ALGORITHM);

        // Confirms that both shared secrets are equal.
        assertArrayEquals(sharedSecret1.getEncoded(),
                sharedSecret2.getEncoded());
    }
}
```

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
