import java.util.Vector;
import java.math.BigInteger;
import java.util.Random;
/**
 * This class implements a finite, modular arithmetic field "Zp" where p is a large prime integer.
 * It contains methods that allow to encrypt and decrypt a secrete file via "Shamir Secret Sharing".
 * @author Albert Manuel Orozco Camacho - alorozco53
 * @version 11.0.25.13
 */
public class Zp {
    
    private BigInteger prime = new BigInteger("208351617316091241234326746312124448251235562226470491514186331217050270460481");
    
    /** Default constructor */
    public Zp() {};
    
    /**
     * This constructor allows the user to set another big prime instead of the default one
     * @param p -- new big prime
     */
    public Zp(String p) {
	setPrime(p);
    }

    /**
     * Sets p as the new prime integer of the field
     * @param p -- new big prime
     */
    public void setPrime(String p) {
	this.prime = new BigInteger(p);
    }

    /**
     * Returns the class' big prime
     * @return BigInteger -- the big prime
     */
    public BigInteger getPrime() {
	return prime;
    }
    
    /**
     * Returns a vector array that represents n points of a polynomial where k was crypted as the independent term
     * @param k -- independent term of a new polynomial
     * @param t -- degree (-1) of such polynomial
     * @param n -- number of evaluations of such polynomial
     * @return Vector[] -- array containing n evaluations
     */
    public Vector[] crypt(BigInteger k, int t, int n) {
	return evaluatePolynomial(buildPolynomial(k.mod(prime),t),n);
    }

    /**
     * Constructs a new array of BigIntegers that represent a t-degree polynomial, by considering 'k' as the independent term.
     * @param k -- independent term of the polynomial
     * @param t -- degree (-1) of the polynomial
     * @return BigInteger[] -- the polynomial
     */
    public BigInteger[] buildPolynomial(BigInteger k, int t) {
	BigInteger coeff = null;
	BigInteger[] polynomial = new BigInteger[t];
	polynomial[0] = k;
	for(int i = 1; i < polynomial.length; i++) {
	    do
		coeff = new BigInteger(prime.bitLength(),new Random());
	    while(coeff.compareTo(prime)>=0 || coeff.compareTo(BigInteger.ZERO)==0);
	    polynomial[i] = coeff;
	}
	return polynomial;
    }

    /**
     * Evaluates the given array of BigIntegers (polynomial) n random times, and returns an array of n evaluations.
     * @param polynomial -- array of BigInteger, where the i-th entry corresponds to polynomial[i]x^i
     * @param n -- number of evaluations to be done
     * @return Vector[] -- array of n evaluations
     */
    public Vector[] evaluatePolynomial(BigInteger[] polynomial, int n) {
	BigInteger coeff = null, fcoeff = new BigInteger("0");
	Vector[] eval = new Vector[n];
	for(int i = 0; i < eval.length; i++) {
	    do
		coeff = new BigInteger(prime.bitLength(),new Random());
	    while(coeff.compareTo(prime)>=0 || coeff.compareTo(BigInteger.ZERO)==0);
	    eval[i] = new Vector(2);
	    eval[i].add(0,coeff);
	    for(int j = 0; j < polynomial.length; j++)
		fcoeff = fcoeff.add(polynomial[j].multiply(coeff.modPow(BigInteger.valueOf((long)j),prime)).mod(prime)).mod(prime);
	    eval[i].add(1,fcoeff);
	    fcoeff = new BigInteger("0");
	}
	return eval;
    }

    /**
     * This method evaluates a polynomial using Lagrange interpolation over an array of points in Zp².
     * In practice, this method returns the "shared secret", that is, f(0) = a0 = K.
     * @param x -- the evaluation value (i.e. f(x))
     * @param points -- array of points in Zp²
     * @return BigInteger -- the "shared secret"
     */
    public BigInteger lagrange(BigInteger x, Vector[] points) {
	BigInteger secret = new BigInteger("0"), numerator = new BigInteger("1"), denominator = new BigInteger("1"), 
	    temp = null, aux = null, quotient = null;
	for(int i = 0; i < points.length; i++) {
	    numerator = new BigInteger("1");
	    denominator = new BigInteger("1");
	    for(int j = 0; j < points.length; j++) {
		if(j != i) {
		    temp = (BigInteger)points[i].elementAt(0);
		    aux = (BigInteger)points[j].elementAt(0);
		    numerator = numerator.multiply(x.subtract(aux).mod(prime)).mod(prime);
		    denominator = denominator.multiply(temp.subtract(aux).mod(prime)).mod(prime);
		}
	    }
	    quotient = numerator.multiply(denominator.modInverse(prime)).mod(prime);
	    secret = secret.add(((BigInteger)points[i].elementAt(1)).multiply(quotient).mod(prime)).mod(prime);
	}
	return secret;
    }
}