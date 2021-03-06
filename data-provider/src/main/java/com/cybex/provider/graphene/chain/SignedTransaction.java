package com.cybex.provider.graphene.chain;

import android.util.Log;

import com.cybex.provider.crypto.Sha256Object;

import java.util.ArrayList;
import java.util.List;

public class SignedTransaction extends Transaction {
    private final static char[] hexArray = "0123456789abcdef".toCharArray();
    transient List<CompactSignature> SignaturesBuffer = new ArrayList<>();
    List<String> signatures = new ArrayList<>();

    public void sign(Types.private_key_type privateKeyType, Sha256Object chain_id) {
        Sha256Object digest = sig_digest(chain_id);
        SignaturesBuffer.add(privateKeyType.getPrivateKey().sign_compact(digest, true));
        signatures.add(bytesToHex(privateKeyType.getPrivateKey().sign_compact(digest, true).data));
    }

    public String sign(Types.private_key_type privateKeyType) {
        Sha256Object digest = sig_digest();
        SignaturesBuffer.add(privateKeyType.getPrivateKey().sign_compact(digest, true));
        signatures.add(bytesToHex(privateKeyType.getPrivateKey().sign_compact(digest, true).data));
        Log.e("withdraw_deposit_hash", signatures.get(0));
        return signatures.get(0);
    }

    private String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
