import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {

    private final BigInteger mod;
    private final BigInteger privateKey;
    private final BigInteger publicKey;
    private final int bitLength = 512;

    public RSA() {
        SecureRandom random = new SecureRandom();
        BigInteger p = new BigInteger(bitLength / 2, 100, random);
        BigInteger q = new BigInteger(bitLength / 2, 100, random);

        mod = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        publicKey = generatePublicKey(phi);
        privateKey = publicKey.modInverse(phi);
    }

    private BigInteger generatePublicKey(BigInteger phi) {
        BigInteger e = BigInteger.valueOf(2);
        while (e.compareTo(phi) < 0) {
            if (e.gcd(phi).equals(BigInteger.ONE)) {
                return e;
            }
            e = e.add(BigInteger.ONE);
        }
        throw new ArithmeticException("Не вдалося знайти відповідний відкритий ключ");
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(publicKey, mod);
    }

    public BigInteger decrypt(BigInteger encryptedMessage) {
        return encryptedMessage.modPow(privateKey, mod);
    }

    public static void main(String[] args) {
        RSA rsa = new RSA();
        String text = "Hello World";
        BigInteger message = new BigInteger(text.getBytes());

        BigInteger encryptedMessage = rsa.encrypt(message);
        System.out.println("Шифроване повідомлення: " + encryptedMessage);

        BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
        System.out.println("Розшифроване повідомлення: " + new String(decryptedMessage.toByteArray()));
    }
}