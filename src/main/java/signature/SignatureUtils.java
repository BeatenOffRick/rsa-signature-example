package signature;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class SignatureUtils {

    private static Signature sig;

    static {
        try {
            sig = Signature.getInstance("SHA256WithRSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public static String signTextByKeyFromFile(String text, String pathToPrivateKey) throws Exception {
        return signText(text, getPrivate(pathToPrivateKey));
    }

    public static String signText(String text, PrivateKey privateKey) throws GeneralSecurityException {
        byte[] data = text.getBytes(StandardCharsets.UTF_8);

        sig.initSign(privateKey);
        sig.update(data);

        byte[] signatureBytes = sig.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private static PrivateKey getPrivate(String pathToPrivateKey)
            throws Exception {

        byte[] keyBytes = Files.readAllBytes(Paths.get(pathToPrivateKey));

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static Boolean validateSignatureWithKeyFromFile(String encodedSignature, String text, String publicKeyBody) throws Exception {
        return validateSignature(encodedSignature, text, getPublic(publicKeyBody));
    }

    public static Boolean validateSignature(String encodedSignature, String text, PublicKey publicKey) throws Exception {
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] signature = Base64.getDecoder().decode(encodedSignature);

        sig.initVerify(publicKey);
        sig.update(textBytes);

        return sig.verify(signature);
    }

    private static PublicKey getPublic(String publicKeyBody) throws Exception {
        PEMParser pemParser = new PEMParser(new FileReader(publicKeyBody));
        PemObject pemObject = pemParser.readPemObject();

        X509EncodedKeySpec spec = new X509EncodedKeySpec(pemObject.getContent());
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static void generateKeysPairToFiles(String privateKeyPath, String publicKeyPath) throws Exception {
        KeyPair keyPair = generateKeyPair();

        writePrivateLeyToFile(keyPair.getPrivate(), privateKeyPath);
        writePublicKeyToFile(keyPair.getPublic(), publicKeyPath);
    }

    private static void writePublicKeyToFile(PublicKey key, String path) throws Exception {
        JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(new FileOutputStream(path)));
        writer.writeObject(key);
        writer.close();
    }

    private static void writePrivateLeyToFile(PrivateKey key, String path) throws Exception{
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key.getEncoded());
        FileOutputStream fos = new FileOutputStream(path);
        fos.write(spec.getEncoded());
        fos.close();
    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keysGenerator = KeyPairGenerator.getInstance("RSA");
        keysGenerator.initialize(2048);
        return keysGenerator.generateKeyPair();
    }
}
