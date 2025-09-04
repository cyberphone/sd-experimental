package com.example;

import java.io.File;

import java.security.KeyPair;
import java.security.PublicKey;

import org.webpki.cbor.*;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.HashAlgorithms;

import org.webpki.util.IO;
import org.webpki.util.UTF8;

public class CreateSD {

    static final String OBJECT_ID = "https://example.com/sd-cbor";

    static StringBuilder template = new StringBuilder();

    static String baseDirectory;

    static CBORMap result = new CBORMap();
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
        byte[] disc = new CBORBytes(disclosure.encode()).encode();
        return new CBORBytes(HashAlgorithms.SHA256.digest(disc));
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

    public static void main(String[] argc) {
        baseDirectory = argc[0];
        template.append(readString("template.html"));

        CBORMap originalSdPayload = 
            CBORDecoder.decode(decodeAndPrintFile("original-ietf-sd-cwt")
                .getTag().get().getArray().get(2).getBytes()).getMap();
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
    
        replace("original-pretty-print", createBox(
            CBORDiagnosticNotation.convert(
                readString("original-pretty-print.dn")).toString()));

        // The following seems a bit constructed but it faitfully
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

        CBORMap temp = decodeAndPrintFile("issuer-key").getMap();
        CBORObject keyId = temp.remove(new CBORInt(2));
        int alg = temp.remove(new CBORInt(3)).getInt32();
        KeyPair issuerKeyPair = CBORKeyPair.convert(temp);
        byte[] cbor = syncEmbeddedSignature(new CBORAsymKeySigner(
                issuerKeyPair.getPrivate(), 
                AsymSignatureAlgorithms.getAlgorithmFromId(alg))
            .setKeyId(keyId)
            .sign(new CBORTag(OBJECT_ID, result)), "current-issuer-signature.dn");

        replace("issued-sd-cwt", createBox(CBORDecoder.decode(cbor).toString()));

        // Just for fun - verify the signature
        new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {

                @Override
                public PublicKey locate(PublicKey optionalPublicKey, 
                                        CBORObject optionalKeyId,
                                        AsymSignatureAlgorithms signatureAlgorithm) {
                    if (optionalPublicKey != null || 
                        optionalKeyId == null ||
                        !keyId.equals(optionalKeyId) ||
                        signatureAlgorithm != AsymSignatureAlgorithms.ECDSA_SHA384) {
                        throw new CryptoException("Non-conforming signature container");
                    }
                    return issuerKeyPair.getPublic();
                }
                
            })
            .setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY, new CBORCryptoUtils.Collector() {

                @Override
                public void foundData(CBORObject object) {
                    String objectId = object.getTag().getCOTXObject().objectId;
                    if (!objectId.equals(OBJECT_ID)) {
                        throw new RuntimeException("Unexpected objectID: " + objectId);
                    }
                }
                
            })
            .setUnprotectedDataPolicy(CBORCryptoUtils.POLICY.MANDATORY)
            .validate(CBORDecoder.decode(cbor));

        temp = decodeAndPrintFile("holder-key").getMap();
       // temp.remove()

        writeString("doc" + File.separator + "index.html", template.toString());
    }

}
