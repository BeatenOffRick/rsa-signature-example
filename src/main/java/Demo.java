import signature.SignatureUtils;

public class Demo {

    public static void main(String[] args) {
        String pathToDirectory = "keys/";
        String publicKeyFile = pathToDirectory + "public.crt";
        String privateKeyFile = pathToDirectory + "private.pub";
        String message = "Show must go on!";

        try {
            SignatureUtils.generateKeysPairToFiles(privateKeyFile, publicKeyFile);
            String signature = SignatureUtils.signTextByKeyFromFile(message, privateKeyFile);
            if (SignatureUtils.validateSignatureWithKeyFromFile(signature, message, publicKeyFile)) {
                System.out.println("Text is valid and signed");
            } else {
                System.out.println("Text is not valid and signature from another text");
            }

            if (SignatureUtils.validateSignatureWithKeyFromFile(signature, "Fake message", publicKeyFile)) {
                System.out.println("Houston we have a problem");
            } else {
                System.out.println("Geronimo! Fake message!");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
