import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TxHandler {

    private UTXOPool utxoPool;

	// Constructor - initializes a TxHandler with the given UTXOPool
	// The UTXOPool is a collection of unspent transaction outputs (UTXOs)
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

	// Returns true if the given transaction is valid and can be added to the UTXOPool
    public boolean isValidTx(Transaction tx) {
        Set<UTXO> claimedUTXOs = new HashSet<>();
        double totalInputValue = 0;
        double totalOutputValue = 0;

        // Check each input
        for (int i = 0; i < tx.numInputs(); i++) {
			// Get the input and the corresponding UTXO
            Transaction.Input input = tx.getInput(i);
			// Create a UTXO object from the input's previous transaction hash and output index
			// The UTXO is the output of the previous transaction that this input is spending
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);

            // (1) Check if the claimed output is in the UTXO pool
            if (!utxoPool.contains(utxo)) {
                return false;
            }

            // (2) Verify the signature
			// Get the output corresponding to the UTXO from the UTXO pool
			// The output contains the value and the public key of the recipient
            Transaction.Output output = utxoPool.getTxOutput(utxo);
			// Get the public key from the output
			// The public key is used to verify the signature of the input
            RSAKey pubKey = output.address;  // Don't cast to PublicKey
			// Get the message to sign, which is the hash of the transaction excluding the input being verified
			// The message is the raw data of the transaction that needs to be signed
            byte[] message = tx.getRawDataToSign(i);
			// Get the signature from the input
			// The signature is the digital signature of the message created by the sender using their private key
            byte[] signature = input.signature;

			// Verify the signature using the public key and the message
			// The signature must match the message signed with the private key of the sender
            if (!verifySignature(pubKey, message, signature)) {
                return false;
            }

            // (3) Check for double spending
			// Check if the UTXO has already been claimed in this transaction
			// A UTXO can only be spent once in a transaction
            if (claimedUTXOs.contains(utxo)) {
                return false;
            }
			// Add the UTXO to the set of claimed UTXOs
			// This prevents double spending of the same UTXO in this transaction
            claimedUTXOs.add(utxo);

			// Add the value of the output to the total input value
			// The total input value is the sum of the values of all outputs being spent in this transaction
            totalInputValue += output.value;
        }

        // Check each output
		// Loop through all outputs of the transaction
		// The outputs are the new UTXOs created by this transaction
		// Each output has a value and an address (public key) of the recipient
        for (Transaction.Output output : tx.getOutputs()) {
            // (4) Check for non-negative output values
			// The value of each output must be non-negative
            if (output.value < 0) {
                return false;
            }
			// Add the value of the output to the total output value
			// The total output value is the sum of the values of all outputs created by this transaction
            totalOutputValue += output.value;
        }

        // (5) Check that input values cover output values
        return totalInputValue >= totalOutputValue;
    }

    private boolean verifySignature(RSAKey pubKey, byte[] message, byte[] signature) {
		// Verify the signature using the public key and the message
        try {
            // Use the RSAKey's own verify method instead of Java's Signature
			// The RSAKey class should have a method to verify the signature
			// The method should take the message and the signature as parameters
            return pubKey.verifySignature(message, signature);
        } catch (Exception e) {
            return false;
        }
    }

    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> validTxs = new ArrayList<>();

        // Loop through all possible transactions
		// Check if each transaction is valid and can be added to the UTXOPool
        boolean changed;
        do {
			// Reset the changed flag to false at the beginning of each iteration
            changed = false;
			// Loop through all transactions in the possible transactions array
			// Check if each transaction is valid and can be added to the UTXOPool
            for (Transaction tx : possibleTxs) {
				// Check if the transaction is not already in the valid transactions list
				// and if it is valid according to the isValidTx method
                if (!validTxs.contains(tx) && isValidTx(tx)) {
					// If the transaction is valid, add it to the valid transactions list
					// The transaction is now considered valid and can be added to the UTXOPool
                    validTxs.add(tx);
                    // Remove consumed UTXOs
					// Loop through all inputs of the transaction
					// The inputs are the UTXOs being spent in this transaction
					// Each input corresponds to a UTXO in the UTXOPool
                    for (Transaction.Input input : tx.getInputs()) {
						// Get the UTXO corresponding to the input
						// The UTXO is the output of the previous transaction that this input is spending
                        UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
						// Remove the UTXO from the UTXOPool
						// The UTXO is now spent and should not be available for future transactions
                        utxoPool.removeUTXO(utxo);
                    }
                    // Add new UTXOs
					// Get the hash of the transaction
					// The hash is a unique identifier for the transaction
                    byte[] txHash = tx.getHash();
					// Loop through all outputs of the transaction
					// Each output has a value and an address (public key) of the recipient
                    for (int i = 0; i < tx.numOutputs(); i++) {
						// Create a UTXO object from the transaction hash and output index
                        UTXO utxo = new UTXO(txHash, i);
						// Get the output corresponding to the UTXO from the transaction
                        utxoPool.addUTXO(utxo, tx.getOutput(i));
                    }
					// Set the changed flag to true to indicate that the UTXOPool has been modified
                    changed = true;
                }
            }
        } while (changed);
		// After processing all transactions, return the valid transactions as an array
        return validTxs.toArray(new Transaction[0]);
    }
}