package com.example.demo;

import ethereum.ckzg4844.CKZG4844JNI;
import ethereum.ckzg4844.ProofAndY;
import org.apache.tomcat.util.buf.HexUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.web3j.crypto.*;


import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {

       RawTransaction tx = TransactionDecoder.decode("0x02f8b00181ff830c3500850acf979cb982b59b94dac17f958d2ee523a2206206994597c13d831ec780b844a9059cbb0000000000000000000000003ea17f81b47edcd4c1479ebd9bb72952e926f80400000000000000000000000000000000000000000000000000000001faa3b500c080a03e70e1f71b18f14afe24411bf82a5476b5447ad2f7b279bff093b7e9fa03dc16a06de5ea72299a5fd15b5e6d1b4ed869c5033ca7d297b5cf75e340c26f2efa6e1410");

       byte[] ss = HexUtils.fromHexString(tx.getData());

        CKZG4844JNI.loadNativeLibrary();
        CKZG4844JNI.loadTrustedSetup("D:\\ZKP\\demo\\src\\main\\resources\\trusted-setup.txt");

       byte[] Hex =  "0x02f87701835a6e8184773594008517bfac7c008303291894ed84ff48378779845cc7c0cb1b012551b573e6c0880244c6791eaa4c0080c001a0bbb20e174fc9d8332a1aecefbe7b0814035a97ead360b78872f44a5ccea88d49a014c918648dd3b496e82bbc2c1a62ce561faf2b68fe1fc7023b9bd2fc3fd706a6".getBytes(StandardCharsets.UTF_8);


              byte[] blob = new byte[131072]; // Your data
        for (int i = 0; i < blob.length; i++) {
           // System.out.println(i);
            if(i<Hex.length) {
                blob[i] = Hex[i];
            } else if (i > 100001) {
                blob[i] = 0;
            } else if (i == 131071) {
                blob[i] = 12;
            }
        }
        System.out.println(HexUtils.toHexString("0xff".getBytes(StandardCharsets.UTF_8)));

        System.out.println(new String(blob));
        System.out.println(HexUtils.toHexString(blob));

       byte[] commitment = CKZG4844JNI.blobToKzgCommitment(blob);

       byte[] hash =  Hash.sha256hash160(blob);

       byte[] z = new byte[32];

        z= Arrays.copyOfRange(HexUtils.toHexString(hash).getBytes(StandardCharsets.UTF_8), 0, 32);

       System.out.println(HexUtils.toHexString(hash));
        System.out.println(HexUtils.toHexString(z));

        ProofAndY proof = CKZG4844JNI.computeKzgProof(blob, z);

        byte[] proof2 =  CKZG4844JNI.computeBlobKzgProof(blob, commitment);

        boolean isValidProof = CKZG4844JNI.verifyKzgProof(commitment, z, proof.getY(), proof.getProof());

                //verifyBlobKzgProof(blob, commitment, proof.getProof());

        boolean isValidProof2 = CKZG4844JNI.verifyBlobKzgProof(blob, commitment, proof2);

        System.out.println(isValidProof);
        System.out.println(isValidProof2);
        SpringApplication.run(DemoApplication.class, args);
    }

}
