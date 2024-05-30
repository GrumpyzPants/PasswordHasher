import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PasswordHasher {
    //private static ArrayList<String> passwordList = new ArrayList<>();
    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {

        Scanner sc = new Scanner(System.in);
        System.out.println("-------------------------------------------------------");
        System.out.println("Please enter a password. \nMust include: Length < 8, Special Character(s), Lowercase & Uppercase characters - \n");
        String password = sc.nextLine();

        Pattern p = Pattern.compile("[^a-z0-9 ]", Pattern.CASE_INSENSITIVE);

        boolean a = false;
        while(!a){
            Matcher m = p.matcher(password);
            boolean b = m.find();

            if(password.length() < 8){
                System.out.println("\nPlease enter a stronger password! Must be longer than 8 characters. \n");
                password = sc.nextLine();
            } else if(!b){
                System.out.println("\nPlease enter a stronger password! Must contain special characters. \n");
                password = sc.nextLine();
            } else {
                a = true;
            }
        }
        System.out.println("-------------------------------------------------------");
        System.out.println("Hashed Password:" + "\n" + hashingF(password));
        System.out.println("-------------------------------------------------------");

        /*
        passwordList.add(hashingF(password));

        System.out.println("\n Please re-enter the password you just created to test for login: ");
        String loginPassword = sc.nextLine();
        String hashedLoginPassword = hashingF(loginPassword);
        System.out.println(hashingF(loginPassword));

        if(passwordList.contains(hashedLoginPassword)){
            System.out.println("Login successful!");
        } else {
            System.out.println("No login found.");
        }
         */

    }

    public static String hashingF(String x) throws InvalidKeySpecException, NoSuchAlgorithmException {
        //Password variation and specifications
        int iterations = 100000;
        int saltLength = 16;
        int keyLength = 256;

        //Salt generator
        SecureRandom sr = new SecureRandom();
        byte[] salt = new byte[saltLength];
        sr.nextBytes(salt);

        //Hashing factory
        char[] passwordChars = x.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hashedPassword = factory.generateSecret(spec).getEncoded();

        byte[] saltedHashedPassword = new byte[salt.length + hashedPassword.length];
        System.arraycopy(salt, 0, saltedHashedPassword, 0, salt.length);
        System.arraycopy(hashedPassword, 0, saltedHashedPassword, salt.length, hashedPassword.length);

        String hexSaltedHashedPassword = bytesToHex(saltedHashedPassword);

        return hexSaltedHashedPassword;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        try (Formatter formatter = new Formatter(result)) {
            for (byte b : bytes) {
                formatter.format("%02x", b);
            }
        }
        return result.toString();
    }
}


