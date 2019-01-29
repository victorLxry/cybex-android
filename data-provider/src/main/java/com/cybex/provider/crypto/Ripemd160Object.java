package com.cybex.provider.crypto;

import com.google.common.io.BaseEncoding;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;

import java.io.Serializable;
import java.lang.reflect.Type;

public class Ripemd160Object implements Serializable {
    public int hash[] = new int[5];

    public static class ripemd160_object_deserializer implements JsonDeserializer<Ripemd160Object> {

        @Override
        public Ripemd160Object deserialize(JsonElement json,
                                           Type typeOfT,
                                           JsonDeserializationContext context) throws JsonParseException {
            Ripemd160Object ripemd160Object = new Ripemd160Object();
            BaseEncoding encoding = BaseEncoding.base16().lowerCase();
            byte[] byteContent = encoding.decode(json.getAsString());
            if (byteContent.length != 20) {
                throw new JsonParseException("Ripemd160Object size not correct.");
            }
            for (int i = 0; i < 5; ++i) {
                ripemd160Object.hash[i] = ((byteContent[i * 4 + 3] & 0xff) << 24) |
                        ((byteContent[i * 4 + 2] & 0xff) << 16) |
                        ((byteContent[i * 4 + 1] & 0xff) << 8) |
                        ((byteContent[i * 4 ] & 0xff));
            }

            return ripemd160Object;
        }
    }
}
