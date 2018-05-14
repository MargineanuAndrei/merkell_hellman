import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Random;
import java.util.Scanner;

public class Merkell_Hellman {

    private BigInteger[] w, b;
    private BigInteger q, r;
    private Random rand = new Random();
    private static final int MAX_CHARS = 150;
    private static final int BINARY_LENGTH = MAX_CHARS * 8;
    private static final Charset UTF8 = Charset.forName("UTF-8");

	// Constructorul clasei
    public Merkell_Hellman() {
        genKeys();
    }

    private void genKeys() {
        int maxBits = 50;

		// w va fi masivul de big inturi
        w = new BigInteger[BINARY_LENGTH];
        // initializez un random big int si adaug 1 pentru procectie pentru ca la generarea random a bin intului poate sa fie si 0
        w[0] = new BigInteger(maxBits, rand).add(BigInteger.ONE);
		// suma masivului w
		BigInteger sum = new BigInteger(w[0].toByteArray());
		// populez masivul cu integeri mari
        for (int i = 1; i < w.length; i++) {
            w[i] = sum.add(new BigInteger(maxBits, rand).add(BigInteger.ONE));
            sum = sum.add(w[i]);
        }
		// generez q random integer mai mare de cit suma masivului w
        q = sum.add(new BigInteger(maxBits, rand).add(BigInteger.ONE));
        r = q.subtract(BigInteger.ONE);
		// generez cheie publica
        b = new BigInteger[BINARY_LENGTH];
        for (int i = 0; i < b.length; i++)
            b[i] = w[i].multiply(r).mod(q);
    }

    // Functie pentru incriptarea mesajului
    public String encryptMsg(String message) {
        if (message.length() > MAX_CHARS)
            throw new IndexOutOfBoundsException("Maximum message length allowed is " + MAX_CHARS + ".");
        if (message.length() <= 0){
            throw new Error("Cannot encrypt an empty string.");
		}
        // covertim mesajul intr-un string binar
        String msgBinary = new BigInteger(message.getBytes(UTF8)).toString(2);
		// mutam 0 la stânga dacă binarul convertit nu este la fel de lung ca secvențele cheie w și b
        if (msgBinary.length() < BINARY_LENGTH) {
            msgBinary = String.format("%0" + (BINARY_LENGTH - msgBinary.length()) + "d", 0) + msgBinary;
        }
        // procudem mesajul final incriptat
        BigInteger result = BigInteger.ZERO;
        for (int i = 0; i < msgBinary.length(); i++) {
            result = result.add(b[i].multiply(new BigInteger(msgBinary.substring(i, i+1))));
        }
        return result.toString();
    }

    // Functie pentru decriptarea mesajului
    public String decryptMsg(String ciphertext) {
        BigInteger tmp = new BigInteger(ciphertext).mod(q).multiply(r.modInverse(q)).mod(q);
        byte[] decrypted_binary = new byte[w.length];

        for (int i = w.length - 1; i >= 0; i--) {
            if (w[i].compareTo(tmp) <= 0) {
                tmp = tmp.subtract(w[i]);
                decrypted_binary[i] = 1;
            } else {
                decrypted_binary[i] = 0;
            }
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < decrypted_binary.length; i++) {
            sb.append(decrypted_binary[i]);
        }
        return new String(new BigInteger(sb.toString(), 2).toByteArray());
    }

    // Functie pentru pornirea procesului
    public static void main(String[] args) {
        Merkell_Hellman crypto = new Merkell_Hellman();
        Scanner input = new Scanner(System.in);
        String message;
        while (true) {
            System.out.println("Introduceti textul care doriti sal incriptati:");
            message = input.nextLine();
            if (message.length() > MAX_CHARS)
                System.out.printf("\nMesajul dumnevoastra trebuie sa aiba maximul de %d caractere! Va rog introduceti din nou.\n", MAX_CHARS);
            else if (message.length() <= 0)
                System.out.println("\nMesajul nu poate fi gol. Va rog incercati din nou.\n");
            else break;
        }

        String encrypted = crypto.encryptMsg(message);
        System.out.println("\n\"" + message + "\"" + " a fost incriptat in:");
        System.out.println(encrypted);

        System.out.println("\nRezultatul decripatarii:");
        System.out.println(crypto.decryptMsg(encrypted));
    }
}
