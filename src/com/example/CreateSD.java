package com.example;

import java.io.File;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;

import org.webpki.cbor.*;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.util.IO;
import org.webpki.util.UTF8;
import org.webpki.util.HexaDecimal;

public class CreateSD {

    static final String OBJECT_ID_SD_CDE = "https://example.com/sd-cde";

    static final String OBJECT_ID_SD_KBT = "https://example.com/sd-kbt";

    static StringBuilder template = new StringBuilder();

    static String baseDirectory;

    static CBORMap result = new CBORMap();
    static HashMap<CBORObject, Boolean> entries = new HashMap<>();

    static CBORInt CNF_MAIN_LBL = new CBORInt(8);
    static CBORInt CNF_ALG_LBL = new CBORInt(2);
    static CBORSimple SIMPLE_59 = new CBORSimple(59);
    
    
    static void writeString(String fileName, String data) {
        IO.writeFile(fileName, UTF8.encode(data));
    }
    
    static String htmlIze(String string) {
        return string.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
                     .replace(" ", "&nbsp;")
                     .replace("\n", "<br>\n");
    }

    static CBORMap readCBOR(String localName) {
        return CBORDiagnosticNotation.convert(readString(localName)).getMap();
    }

    static String readString(String localName) {
        return UTF8.decode(IO.readFile(baseDirectory + File.separator + localName));
    }

    static String createBox(String raw) {
        return "<div class='webpkihexbox' style='display:block'>" +
               htmlIze(raw) +
               "</div>";
    }

    static void replace(String holder, String text) {
        int index = template.indexOf("@" + holder + "@");
        if (index <= 0) {
            throw new RuntimeException("no find: " + holder);
        }
        template.replace(index, index + holder.length() + 2, text);
    }

    static CBORBytes claim(CBORObject disclosure) {
        return new CBORBytes(HashAlgorithms.SHA256.digest(disclosure.encode()));
    }

    static CBORObject decodeAndPrintFile(String baseName) {
        String rawDNString = readString(baseName + ".dn");
        replace(baseName, createBox(rawDNString));
        return CBORDiagnosticNotation.convert(rawDNString);
    }

    static CBORObject removeSignature(CBORObject signedObject) {
        CBORObject modified = signedObject.clone();
        modified.getTag().getCOTXObject()
            .object.getMap().get(CBORCryptoConstants.CSF_CONTAINER_LBL)
                .getMap().remove(CBORCryptoConstants.CSF_SIGNATURE_LBL);
        return modified;
    }

    static byte[] syncEmbeddedSignature(CBORObject signature, String refFile) {
        try {
            CBORObject refSignature = CBORDiagnosticNotation.convert(readString(refFile));
            if (removeSignature(signature).equals(removeSignature(refSignature))) {
                signature = refSignature;
            } else {
                throw new RuntimeException("""
******************************************
           Updated Structure?
******************************************""");
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            System.out.println("wrote: " + refFile);
            writeString(refFile, signature.toString());
        }
        return signature.encode();
    }

    static void addBlinded(CBORObject disclosure) {
        if (entries.put(disclosure, false) != null) {
            throw new RuntimeException("Duplicate disclosure: " + disclosure);
        }
    }

    static void fetch59(CBORObject disclosures) {
        for (CBORObject element : disclosures.getArray().toArray()) {
            addBlinded(element);
        }
    }

    public static void main(String[] argc) {
        baseDirectory = argc[0];
        template.append(readString("template.html"));

        CBORObject sdCwtOriginal = decodeAndPrintFile("original-ietf-sd-cwt");

        CBORMap originalSdPayload = 
            CBORDecoder.decode(sdCwtOriginal.getTag().get().getArray().get(2).getBytes()).getMap();
        // Fetch original instance data and "cnf"
        for (CBORObject key : originalSdPayload.getKeys()) {
            if (key instanceof CBORInt keyinst && keyinst.getInt32() < 500) {
                result.set(key, originalSdPayload.get(key));
            }
        }

        result.get(CNF_MAIN_LBL).getMap().set(
            CNF_ALG_LBL, 
            new CBORInt(HashAlgorithms.SHA256.getCoseAlgorithmId()));
 
        CBORArray disclosures = decodeAndPrintFile("disclosures").getArray();
    
        replace("original-sd-cwt-pretty-print", createBox(sdCwtOriginal.toString()));

        // The following seems a bit constructed but it faithfully
        // follows the original :)

        // The disclosures in clear.
        result.set(CBORCryptoConstants.CSF_UNPROTECTED_LBL, disclosures);

        // From the IETF original:
        result.set(new CBORInt(500), new CBORBoolean(true))
              .set(new CBORInt(502), new CBORArray()
                  .add(new CBORTag(60, claim(disclosures.get(1))))
                  .add(new CBORTag(60, claim(disclosures.get(2))))
                  .add(new CBORInt(1674004740)))
              .set(new CBORInt(503), new CBORMap()
                  .set(new CBORString("country"), new CBORString("us"))
                  .set(SIMPLE_59, new CBORArray()
                      .add(claim(disclosures.get(3)))
                      .add(claim(disclosures.get(4)))))
              .set(SIMPLE_59, new CBORArray()
                  .add(claim(disclosures.get(0))));

        CBORMap issuerKey = decodeAndPrintFile("issuer-key").getMap();
        CBORObject keyId = issuerKey.remove(new CBORInt(2));
        int alg = issuerKey.remove(new CBORInt(3)).getInt32();
        KeyPair issuerKeyPair = CBORKeyPair.convert(issuerKey);
        byte[] cbor = syncEmbeddedSignature(new CBORAsymKeySigner(
                issuerKeyPair.getPrivate(), 
                AsymSignatureAlgorithms.getAlgorithmFromId(alg))
            .setKeyId(keyId)
            .sign(new CBORTag(OBJECT_ID_SD_CDE, result)), "current-issuer-signature.dn");

        // Raw, but rather pretty anyway
        replace("issued-sd-cwt", createBox(CBORDecoder.decode(cbor).toString()));

        // Just for "fun" - verify the signature
        CBORObject decoded = CBORDecoder.decode(cbor);

        // Enforce strict policies!
        new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {

                @Override
                public PublicKey locate(PublicKey optionalPublicKey, 
                                        CBORObject optionalKeyId,
                                        AsymSignatureAlgorithms signatureAlgorithm) {
                        // No inline public key
                    if (optionalPublicKey != null || 
                        // Must have a keyId
                        optionalKeyId == null ||
                        // That verify the keyId
                        !keyId.equals(optionalKeyId) ||
                        // Verify algorithm
                        signatureAlgorithm != AsymSignatureAlgorithms.ECDSA_SHA384) {
                        throw new CryptoException("Non-conforming signature container");
                    }
                    return issuerKeyPair.getPublic();
                }
                
            })
            // Non-standard: must hava a COTX tag with a specfic ID
            .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {

                @Override
                public void foundData(CBORObject object) {
                    String objectId = object.getTag().getCOTXObject().objectId;
                    if (!objectId.equals(OBJECT_ID_SD_CDE)) {
                        throw new RuntimeException("Unexpected objectID: " + objectId);
                    }
                }
                
            })
            // Non-standard: permit unprotected elements
            .setUnprotectedDataPolicy(CBORCryptoUtils.POLICY.MANDATORY)
            .validate(decoded);

        // Now ckeck the disclosures!

        // Collect the signed blinded claims
        CBORMap globalMap = decoded.getTag().getCOTXObject().object.getMap();
        for (CBORObject entry : globalMap.getKeys()) {
            if (entry instanceof CBORInt i32 && i32.getInt32() > 8) {
                CBORObject object = globalMap.get(entry);
                if (object instanceof CBORArray arr) {
                    for (CBORObject o : arr.toArray()) {
                        if (o instanceof CBORTag tag && tag.getTagNumber() == 60) {
                            addBlinded(tag.get());
                        }
                    }
                } else if (object instanceof CBORMap map) {
                    for (CBORObject key : map.getKeys()) {
                        if (key.equals(SIMPLE_59)) {
                            fetch59(map.get(key));
                            // Uncomment for testing.
//                            addBlinded(new CBORString("nonsense"));
                        }
                    }
                }
                continue;
            }
            if (entry.equals(SIMPLE_59)) {
                // Coomment away for testing.
                fetch59(globalMap.get(entry));
            }
        }
        // Uncomment next line for testing.
//        globalMap.get(CBORCryptoConstants.CSF_UNPROTECTED_LBL).getArray().add(new CBORString("no such claim"));
        // Fetch the clear text disclosures and verify thair signed and blinded counterpart
        for (CBORObject element : 
                globalMap.get(CBORCryptoConstants.CSF_UNPROTECTED_LBL).getArray().toArray()) {
            CBORBytes disclosure = claim(element);
            if (entries.get(disclosure) == null) {
                throw new RuntimeException("Missing signed disclosure for: " + element);
            }
            entries.put(disclosure, true);
        }
        // Are there signed disclosures missing their clear-text counterpart?
        for (CBORObject key : entries.keySet()) {
            if (!entries.get(key)) {
                throw new RuntimeException("Missing unsigned disclosure for: " + key);
            }
        }
        // We did it!

        // Now use it!
        CBORMap holderKey = decodeAndPrintFile("holder-key").getMap();
        // Remove alg from the key.
        holderKey.remove(new CBORInt(3));
        KeyPair holderKeyPair = CBORKeyPair.convert(holderKey);

        // Now remove the disclosures we won't disclose
        CBORArray disclosed = decoded.getTag().getCOTXObject().object.getMap()
            .get(CBORCryptoConstants.CSF_UNPROTECTED_LBL).getArray();
            disclosed.remove(2);
            disclosed.remove(3);
        CBORMap kbtMap = new CBORMap()
            .set(new CBORInt(13), decoded)
            .set(new CBORInt(3), new CBORString("https://verifier.example/app"))
            .set(new CBORInt(6), new CBORInt(1725244237))
            .set(new CBORInt(39), new CBORBytes(HexaDecimal.decode("8c0f5f523b95bea44a9a48c649240803")));
        cbor = syncEmbeddedSignature(new CBORAsymKeySigner(holderKeyPair.getPrivate()).sign(
            new CBORTag(OBJECT_ID_SD_KBT, kbtMap)), "current-holder-signature.dn");
        replace("sd-kbt-pretty-print", createBox(CBORDecoder.decode(cbor).toString()));
        decodeAndPrintFile("original-ietf-sd-kbt");

        writeString("doc" + File.separator + "index.html", template.toString());
    }

}
