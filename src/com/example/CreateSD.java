package com.example;

import java.io.File;

import org.webpki.cbor.*;
import org.webpki.util.IO;
import org.webpki.util.UTF8;

public class CreateSD {
    static CBORMap requestMap;
    static String requestDN;

    static CBORMap result = new CBORMap();

    static CBORMap readCBOR(String[] argc, String localName) {
        return CBORDiagnosticNotation.convert(readDNText(argc, localName)).getMap();
    }

    static String readDNText(String[] argc, String localName) {
        return UTF8.decode(IO.readFile(argc[0] + File.separator + localName));
    }

    public static void main(String[] argc) {
        requestDN = readDNText(argc, "request.dn");
        requestMap = CBORDiagnosticNotation.convert(requestDN).getMap();
        
        for (CBORObject key : requestMap.getKeys()) {
            if (key.getInt32() < 500) {
                CBORObject value = requestMap.remove(key);
                result.set(key, value);
            }
        }

        System.out.println("Got here!" + result.toString());
        System.out.println("Got here!" + requestMap.toString());
    }

}
