package uk.ac.nottingham.cryptography.tests.modes;

/**
 * Represents a single XTS-AES test vector from the test vector files.
 */
public record XTSTestVector(
        boolean encrypt,
        int dataUnitLen,
        String key,
        String sector,
        String plaintext,
        String ciphertext
) {
    @Override
    public String toString() {
        String mode = this.encrypt() ? "Encrypt" : "Decrypt";
        String key = this.key();
        String sector = this.sector();
        return mode +
                ", Key: " + key.substring(0, 4) + "..." + key.substring(key.length() - 4) +
                ", Sector: " + sector.substring(0, 4) + "..." + sector.substring(sector.length() - 4) ;
    }
}
