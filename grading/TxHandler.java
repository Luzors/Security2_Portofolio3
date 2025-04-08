import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TxHandler {

    private UTXOPool utxoPool;

    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    public boolean isValidTx(Transaction tx) {
        Set<UTXO> claimedUTXOs = new HashSet<>();
        double totalInputValue = 0;
        double totalOutputValue = 0;

        // Check each input
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input input = tx.getInput(i);
            UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);

            // (1) Check if the claimed output is in the UTXO pool
            if (!utxoPool.contains(utxo)) {
                return false;
            }

            // (2) Verify the signature
            Transaction.Output output = utxoPool.getTxOutput(utxo);
            RSAKey pubKey = output.address;  // Don't cast to PublicKey
            byte[] message = tx.getRawDataToSign(i);
            byte[] signature = input.signature;

            if (!verifySignature(pubKey, message, signature)) {
                return false;
            }

            // (3) Check for double spending
            if (claimedUTXOs.contains(utxo)) {
                return false;
            }
            claimedUTXOs.add(utxo);

            totalInputValue += output.value;
        }

        // Check each output
        for (Transaction.Output output : tx.getOutputs()) {
            // (4) Check for non-negative output values
            if (output.value < 0) {
                return false;
            }
            totalOutputValue += output.value;
        }

        // (5) Check that input values cover output values
        return totalInputValue >= totalOutputValue;
    }

    private boolean verifySignature(RSAKey pubKey, byte[] message, byte[] signature) {
        try {
            // Use the RSAKey's own verify method instead of Java's Signature
            return pubKey.verifySignature(message, signature);
        } catch (Exception e) {
            return false;
        }
    }

    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        List<Transaction> validTxs = new ArrayList<>();

        // We need to handle dependencies between transactions, so we may need multiple passes
        boolean changed;
        do {
            changed = false;
            for (Transaction tx : possibleTxs) {
                if (!validTxs.contains(tx) && isValidTx(tx)) {
                    validTxs.add(tx);
                    // Remove consumed UTXOs
                    for (Transaction.Input input : tx.getInputs()) {
                        UTXO utxo = new UTXO(input.prevTxHash, input.outputIndex);
                        utxoPool.removeUTXO(utxo);
                    }
                    // Add new UTXOs
                    byte[] txHash = tx.getHash();
                    for (int i = 0; i < tx.numOutputs(); i++) {
                        UTXO utxo = new UTXO(txHash, i);
                        utxoPool.addUTXO(utxo, tx.getOutput(i));
                    }
                    changed = true;
                }
            }
        } while (changed);

        return validTxs.toArray(new Transaction[0]);
    }
}