package com.example;

import java.io.File;

import java.security.KeyPair;

import org.webpki.cbor.*;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.util.Base64URL;
import org.webpki.util.HexaDecimal;
import org.webpki.util.IO;
import org.webpki.util.UTF8;

public class CreateSD {

    static final String OBJECT_ID = "https://example.com/sd-cbor";

    static CBORMap requestMap;
    static StringBuilder template = new StringBuilder();
    static String requestDN;

    static String baseDirectory;

    static KeyPair issuerPair;

    static CBORMap result = new CBORMap();
    
    
    static void writeString(String fileName, String data) {
        IO.writeFile(fileName, UTF8.encode(data));
    }
    
    static String htmlIze(String string) {
        return string.replace("&", "&amp;")
                     .replace("<", "&lt;")
                     .replace(">", "&gt;")
                     .replace(" ", "&nbsp;")
                     .replace("\n", "<br>");
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

    static CBORSimple SIMPLE_59 = new CBORSimple(59);
    static final CBORArray DISCLOSURES = 
    CBORDiagnosticNotation.convert("""
            [ / these are all the disclosures /
        [
            /salt/   h'bae611067bb823486797da1ebbb52f83',
            /value/  "ABCD-123456",
            /claim/  501   / inspector_license_number /
        ],
        [
            /salt/   h'8de86a012b3043ae6e4457b9e1aaab80',
            /value/  1549560720   / inspected 7-Feb-2019 /
        ],
        [
            /salt/   h'7af7084b50badeb57d49ea34627c7a52',
            /value/  1612560720   / inspected 4-Feb-2021 /
        ],
        [
            /salt/   h'ec615c3035d5a4ff2f5ae29ded683c8e',
            /value/  "ca",
            /claim/  "region"   / region=California /
        ],
        [
            /salt/   h'37c23d4ec4db0806601e6b6dc6670df9',
            /value/  "94188",
            /claim/  "postal_code"
        ]
    ]
            """).getArray();

    static void replace(String holder, String text) {
        int index = template.indexOf("@" + holder + "@");
        if (index <= 0) {
            throw new RuntimeException("no find: " + holder);
        }
        template.replace(index, index + holder.length() + 2, text);
    }

    static CBORBytes claim(int index) {
        byte[] disc = new CBORBytes(DISCLOSURES.get(index).encode()).encode();
        return new CBORBytes(HashAlgorithms.SHA256.digest(disc));
    }

    public static void main(String[] argc) {
        System.out.println(
   HexaDecimal.encode(HashAlgorithms.SHA256.digest(
            HexaDecimal.decode(
              //  "82507AF7084B50BADEB57D49EA34627C7A521A601DB950"
                "581c8350ec615c3035d5a4ff2f5ae29ded683c8e62636166726567696f6e"
                
                ))));
 
        String sdjwt = Base64URL.encode(UTF8.encode("[\"lklxF5jMYlGTPUovMNIvCA\", \"US\"]"));
        System.out.println(sdjwt);
        System.out.println(
   Base64URL.encode(HashAlgorithms.SHA256.digest(
            UTF8.encode(sdjwt))));

        sdjwt = Base64URL.encode(UTF8.encode("[\"eluV5Og3gSNII8EYnsxA_A\", \"family_name\", \"Doe\"]"));
        System.out.println(sdjwt);
        System.out.println(
   Base64URL.encode(HashAlgorithms.SHA256.digest(
            UTF8.encode(sdjwt))));



        baseDirectory = argc[0];
        template.append(readString("template.html"));
        requestDN = readString("request.dn");
        replace("input", createBox(requestDN));
        String ikey = readString("ikey.dn");
        CBORMap temp = CBORDiagnosticNotation.convert(ikey).getMap();
        CBORObject kid = temp.remove(new CBORInt(2));
        int alg = temp.remove(new CBORInt(3)).getInt32();
        issuerPair = CBORKeyPair.convert(temp);
        replace("ikey", createBox(ikey));
        requestMap = CBORDiagnosticNotation.convert(requestDN).getMap();
        requestMap.get(new CBORInt(8)).getMap()
            .set(new CBORInt(2), new CBORInt(-16));
        
        for (CBORObject key : requestMap.getKeys()) {
            if (key.getInt32() < 500) {
                CBORObject value = requestMap.remove(key);
                result.set(key, value);
            }
        }
        for (CBORObject key : requestMap.getKeys()) {
            CBORObject mapKey;
            CBORObject mapValue;
            switch (key.getInt32()) {
                case 500 -> {
                    mapKey = key;
                    mapValue = new CBORBoolean(true);
                }

                case 501 -> {
                    mapKey = SIMPLE_59;
                    mapValue = new CBORArray().add(claim(0));
                }

                case 502 -> {
                    mapKey = key;
                    mapValue = new CBORMap().set(new CBORString("country"), new CBORString("us"))
                        .set(SIMPLE_59,
                    new CBORArray().add(claim(3)).add(claim(4)));
                }
  
                case 503 -> {
                    mapKey = key;
                    mapValue = new CBORArray().add(new CBORBoolean(true));
                }
 
                default ->
                    throw new RuntimeException("Switch");
            };
            result.set(mapKey, mapValue);
        }
  
        result.set(CBORCryptoConstants.CSF_UNPROTECTED_LBL,
                   DISCLOSURES);
        byte[] cbor = new CBORAsymKeySigner(
                issuerPair.getPrivate(), 
                AsymSignatureAlgorithms.getAlgorithmFromId(alg))
            .setKeyId(kid)
            .sign(new CBORTag(OBJECT_ID, result)).encode();
        replace("sd", createBox(CBORDecoder.decode(cbor).toString()));

        writeString("doc" + File.separator + "index.html", template.toString());
    }

}
