/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.tomcat.util.security;

import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.buf.ByteChunk;

public class TestConstantTime {

    // equals(String, String, boolean)

    @Test
    public void testStringSameReference() {
        String s = "The quick brown fox";
        Assert.assertTrue(ConstantTime.equals(s, s, false));
        Assert.assertTrue(ConstantTime.equals(s, s, true));
    }


    @Test
    public void testStringEqual() {
        // Deliberately not the same String instance
        String other = new StringBuilder("secret").toString();
        Assert.assertTrue(ConstantTime.equals("secret", other, false));
        Assert.assertTrue(ConstantTime.equals("secret", other, true));
    }


    @Test
    public void testStringNotEqualSameLength() {
        Assert.assertFalse(ConstantTime.equals("secret", "secreT", false));
        Assert.assertFalse(ConstantTime.equals("secret", "Xecret", false));
        Assert.assertFalse(ConstantTime.equals("secret", "xxxxxx", true));
    }


    @Test
    public void testStringIgnoreCase() {
        Assert.assertTrue(ConstantTime.equals("SecReT", "sEcrEt", true));
        Assert.assertFalse(ConstantTime.equals("SecReT", "sEcrEt", false));
    }


    @Test
    public void testStringNull() {
        Assert.assertTrue(ConstantTime.equals(null, null, false));
        Assert.assertTrue(ConstantTime.equals(null, null, true));
        Assert.assertFalse(ConstantTime.equals("secret", null, false));
        Assert.assertFalse(ConstantTime.equals(null, "secret", false));
    }


    @Test
    public void testStringDifferentLength() {
        // First shorter than second
        Assert.assertFalse(ConstantTime.equals("secre", "secret", false));
        // First longer than second
        Assert.assertFalse(ConstantTime.equals("secrets", "secret", false));
        // Much longer - exercises the index2 clamping
        Assert.assertFalse(ConstantTime.equals("secretsecretsecret", "secret", false));
        Assert.assertFalse(ConstantTime.equals("secretsecretsecret", "secret", true));
    }


    @Test
    public void testStringEmpty() {
        Assert.assertTrue(ConstantTime.equals("", "", false));
        Assert.assertTrue(ConstantTime.equals("", "", true));
        Assert.assertFalse(ConstantTime.equals("secret", "", false));
        Assert.assertFalse(ConstantTime.equals("", "secret", false));
    }


    // equals(ByteChunk, String)

    private static ByteChunk chunk(String data) {
        byte[] bytes = data.getBytes(StandardCharsets.ISO_8859_1);
        ByteChunk bc = new ByteChunk();
        bc.setBytes(bytes, 0, bytes.length);
        return bc;
    }


    private static ByteChunk chunk(String buffer, int start, int length) {
        byte[] bytes = buffer.getBytes(StandardCharsets.ISO_8859_1);
        ByteChunk bc = new ByteChunk();
        bc.setBytes(bytes, start, length);
        return bc;
    }


    private static ByteChunk chunk(byte[] bytes, int start, int length) {
        ByteChunk bc = new ByteChunk();
        bc.setBytes(bytes, start, length);
        return bc;
    }


    /*
     * Source files are compiled as ISO-8859-1 so non-ASCII characters are built from their code points rather than
     * written as literals.
     */
    private static String string(int... codePoints) {
        StringBuilder sb = new StringBuilder(codePoints.length);
        for (int codePoint : codePoints) {
            sb.append((char) codePoint);
        }
        return sb.toString();
    }


    @Test
    public void testByteChunkEqual() {
        Assert.assertTrue(ConstantTime.equals(chunk("secret"), "secret"));
    }


    @Test
    public void testByteChunkNotEqual() {
        Assert.assertFalse(ConstantTime.equals(chunk("secret"), "secreT"));
        Assert.assertFalse(ConstantTime.equals(chunk("Xecret"), "secret"));
    }


    @Test
    public void testByteChunkIsCaseSensitive() {
        Assert.assertFalse(ConstantTime.equals(chunk("SECRET"), "secret"));
    }


    /*
     * The ByteChunk data does not have to start at index 0 of the underlying byte[]. AJP messages always place the
     * attribute value part way through the packet buffer so this is the normal case, not the exception.
     */
    @Test
    public void testByteChunkWithOffsetEqual() {
        Assert.assertTrue(ConstantTime.equals(chunk("XXXsecret", 3, 6), "secret"));
        Assert.assertTrue(ConstantTime.equals(chunk("XXXsecretYYY", 3, 6), "secret"));
    }


    @Test
    public void testByteChunkWithOffsetNotEqual() {
        Assert.assertFalse(ConstantTime.equals(chunk("XXXsecreTYYY", 3, 6), "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("XXXwrongxYYY", 3, 6), "secret"));
    }


    /*
     * If the offset is ignored, the comparison reads the start of the buffer rather than the chunk. Here the expected
     * value appears at the start of the buffer while the chunk itself holds something else, so ignoring the offset
     * would report a match for a value that does not match.
     */
    @Test
    public void testByteChunkWithOffsetNoFalsePositive() {
        Assert.assertFalse(ConstantTime.equals(chunk("secretYYYwrong", 9, 5), "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("secretYYYWRONG!", 9, 6), "secret"));
    }


    /*
     * Bytes have to be read as unsigned values. Without the 0xFF mask, any byte with the high bit set is negative and
     * can never compare equal to the character it represents.
     */
    @Test
    public void testByteChunkHighBytesEqual() {
        byte[] bytes = new byte[] { (byte) 0x80, (byte) 0xA9, (byte) 0xE9, (byte) 0xFF };
        Assert.assertTrue(ConstantTime.equals(chunk(bytes, 0, 4), string(0x80, 0xA9, 0xE9, 0xFF)));
    }


    @Test
    public void testByteChunkHighBytesWithOffsetEqual() {
        byte[] bytes = new byte[] { 0x41, 0x42, 0x43, (byte) 0xE9, (byte) 0xFF, 0x44 };
        Assert.assertTrue(ConstantTime.equals(chunk(bytes, 3, 2), string(0xE9, 0xFF)));
    }


    @Test
    public void testByteChunkHighBytesNotEqual() {
        byte[] bytes = new byte[] { (byte) 0xE9 };
        Assert.assertFalse(ConstantTime.equals(chunk(bytes, 0, 1), string(0xEA)));
        // 0xE9 read as an unsigned byte is 233. It must not match a character that merely shares the low byte.
        Assert.assertFalse(ConstantTime.equals(chunk(bytes, 0, 1), string(0x1FE9)));
    }


    @Test
    public void testByteChunkNull() {
        Assert.assertTrue(ConstantTime.equals((ByteChunk) null, null));
        Assert.assertFalse(ConstantTime.equals((ByteChunk) null, "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("secret"), null));
    }


    @Test
    public void testByteChunkDifferentLength() {
        // ByteChunk shorter than the String
        Assert.assertFalse(ConstantTime.equals(chunk("secre"), "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("XXXsecre", 3, 5), "secret"));
        // ByteChunk longer than the String
        Assert.assertFalse(ConstantTime.equals(chunk("secrets"), "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("XXXsecrets", 3, 7), "secret"));
        // Much longer - exercises the index2 clamping
        Assert.assertFalse(ConstantTime.equals(chunk("secretsecretsecret"), "secret"));
    }


    @Test
    public void testByteChunkEmpty() {
        Assert.assertTrue(ConstantTime.equals(chunk(""), ""));
        Assert.assertTrue(ConstantTime.equals(new ByteChunk(), ""));
        Assert.assertFalse(ConstantTime.equals(chunk("secret"), ""));
        Assert.assertFalse(ConstantTime.equals(chunk(""), "secret"));
        Assert.assertFalse(ConstantTime.equals(new ByteChunk(), "secret"));
        // An empty chunk that still carries an offset
        Assert.assertTrue(ConstantTime.equals(chunk("XXXXXX", 3, 0), ""));
        Assert.assertFalse(ConstantTime.equals(chunk("secret", 3, 0), "secret"));
    }


    // equals(byte[], byte[])

    @Test
    public void testByteArrayEqual() {
        Assert.assertTrue(ConstantTime.equals("secret".getBytes(StandardCharsets.ISO_8859_1),
                "secret".getBytes(StandardCharsets.ISO_8859_1)));
        Assert.assertTrue(ConstantTime.equals(new byte[0], new byte[0]));
    }


    @Test
    public void testByteArrayNotEqual() {
        Assert.assertFalse(ConstantTime.equals("secret".getBytes(StandardCharsets.ISO_8859_1),
                "secreT".getBytes(StandardCharsets.ISO_8859_1)));
        Assert.assertFalse(ConstantTime.equals(new byte[] { (byte) 0xE9 }, new byte[] { (byte) 0xEA }));
    }


    @Test
    public void testByteArrayDifferentLength() {
        Assert.assertFalse(ConstantTime.equals("secret".getBytes(StandardCharsets.ISO_8859_1),
                "secrets".getBytes(StandardCharsets.ISO_8859_1)));
        Assert.assertFalse(ConstantTime.equals("secret".getBytes(StandardCharsets.ISO_8859_1), new byte[0]));
    }


    @Test
    public void testByteArrayNull() {
        Assert.assertTrue(ConstantTime.equals((byte[]) null, (byte[]) null));
        Assert.assertFalse(ConstantTime.equals("secret".getBytes(StandardCharsets.ISO_8859_1), null));
        Assert.assertFalse(ConstantTime.equals(null, "secret".getBytes(StandardCharsets.ISO_8859_1)));
    }
}
