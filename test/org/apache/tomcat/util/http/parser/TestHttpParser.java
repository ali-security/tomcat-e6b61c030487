/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.tomcat.util.http.parser;

import org.junit.Assert;
import org.junit.Test;

public class TestHttpParser {

    @Test
    public void testTokenDel() {
        Assert.assertFalse("DEL is not a token", HttpParser.isToken(127));
    }


    @Test
    public void testAbsolutePathRelaxedLargeInvalid() {
        HttpParser httpParser = new HttpParser(null, null);
        Assert.assertFalse(httpParser.isAbsolutePathRelaxed(Integer.MAX_VALUE));
    }


    @Test
    public void testAbsolutePathRelaxed01() {
        HttpParser httpParser = new HttpParser(null, null);
        Assert.assertFalse(httpParser.isAbsolutePathRelaxed('{'));
    }


    @Test
    public void testAbsolutePathRelaxed02() {
        HttpParser httpParser = new HttpParser("{", null);
        Assert.assertTrue(httpParser.isAbsolutePathRelaxed('{'));
    }


    @Test
    public void testAbsolutePathRelaxed03() {
        HttpParser httpParser = new HttpParser(null, "{");
        Assert.assertFalse(httpParser.isAbsolutePathRelaxed('{'));
    }


    @Test
    public void testAbsolutePathRelaxed04() {
        HttpParser httpParser = new HttpParser("\u1000", null);
        Assert.assertFalse(httpParser.isAbsolutePathRelaxed('{'));
    }


    @Test
    public void testAbsolutePathRelaxed05() {
        HttpParser httpParser = new HttpParser("", null);
        Assert.assertFalse(httpParser.isAbsolutePathRelaxed('{'));
    }


    @Test
    public void testQueryRelaxedLargeInvalid() {
        HttpParser httpParser = new HttpParser(null, null);
        Assert.assertFalse(httpParser.isQueryRelaxed(Integer.MAX_VALUE));
    }


    @Test
    public void testRequestTargetLargeInvalid() {
        Assert.assertTrue(HttpParser.isNotRequestTarget(Integer.MAX_VALUE));
    }


    @Test
    public void testHttpProtocolLargeInvalid() {
        Assert.assertFalse(HttpParser.isHttpProtocol(Integer.MAX_VALUE));
    }


    @Test
    public void testUserInfoLargeInvalid() {
        Assert.assertFalse(HttpParser.isUserInfo(Integer.MAX_VALUE));
    }


    @Test
    public void testAbsolutePathLargeInvalid() {
        Assert.assertFalse(HttpParser.isAbsolutePath(Integer.MAX_VALUE));
    }


    @Test
    public void testQueryLargeInvalid() {
        Assert.assertFalse(HttpParser.isQuery(Integer.MAX_VALUE));
    }


    @Test
    public void testUnquoteNull() {
        Assert.assertNull(HttpParser.unquote(null));
    }


    @Test
    public void testUnquoteShort() {
        String shortText = "a";
        Assert.assertEquals(shortText, HttpParser.unquote(shortText));
    }


    @Test
    public void testUnquoteUnquoted() {
        String shortText = "abcde";
        Assert.assertEquals(shortText, HttpParser.unquote(shortText));
    }


    @Test
    public void testUnquoteEscaped() {
        // Note: Test string is also Java escaped
        String shortText = "\"ab\\\"ab\"";
        String result = "ab\"ab";
        Assert.assertEquals(result, HttpParser.unquote(shortText));
    }


    @Test
    public void testUnquoteUnquotedEscaped() {
        // Note: Test string is also Java escaped
        String shortText = "ab\\\"ab";
        String result = "ab\"ab";
        Assert.assertEquals(result, HttpParser.unquote(shortText));
    }


    @Test
    public void testUnquoteInvalid01() {
        // Note: Test string is also Java escaped
        String shortText = "aaa\\";
        Assert.assertNull(shortText, HttpParser.unquote(shortText));
    }


    @Test
    public void testTokenStringNull() {
        Assert.assertFalse(HttpParser.isToken(null));
    }


    @Test
    public void testTokenStringEmpty() {
        Assert.assertFalse(HttpParser.isToken(""));
    }


    @Test
    public void testTokenStringLws01() {
        Assert.assertFalse(HttpParser.isToken(" "));
    }


    @Test
    public void testTokenStringLws02() {
        Assert.assertFalse(HttpParser.isToken(" aaa"));
    }


    @Test
    public void testTokenStringLws03() {
        Assert.assertFalse(HttpParser.isToken("\taaa"));
    }


    @Test
    public void testTokenStringValid() {
        Assert.assertTrue(HttpParser.isToken("token"));
    }


    @Test
    public void testFieldVCharFullRange() {
        for (int i = 0; i < 256; i++) {
            // RFC 9110: field-vchar = VCHAR / obs-text, VCHAR = %x21-7E, obs-text = %x80-FF
            boolean expected = i >= 0x21 && i <= 0x7E || i >= 0x80 && i <= 0xFF;
            Assert.assertEquals("Character [" + i + "]", Boolean.valueOf(expected),
                    Boolean.valueOf(HttpParser.isFieldVChar(i)));
        }
    }


    @Test
    public void testFieldContentFullRange() {
        for (int i = 0; i < 256; i++) {
            // RFC 9110: field-content characters are field-vchar plus SP and HTAB (only between field-vchars)
            boolean expected = i >= 0x21 && i <= 0x7E || i >= 0x80 && i <= 0xFF || i == ' ' || i == '\t';
            Assert.assertEquals("Character [" + i + "]", Boolean.valueOf(expected),
                    Boolean.valueOf(HttpParser.isFieldContent(i)));
        }
    }


    @Test
    public void testFieldVCharOutOfRange() {
        Assert.assertFalse(HttpParser.isFieldVChar(-1));
        Assert.assertFalse(HttpParser.isFieldVChar(256));
        // Sign extended byte 0xE9
        Assert.assertFalse(HttpParser.isFieldVChar(0xFFE9));
        Assert.assertFalse(HttpParser.isFieldVChar(Integer.MAX_VALUE));
        Assert.assertFalse(HttpParser.isFieldContent(-1));
        Assert.assertFalse(HttpParser.isFieldContent(256));
        Assert.assertFalse(HttpParser.isFieldContent(0xFFE9));
        Assert.assertFalse(HttpParser.isFieldContent(Integer.MAX_VALUE));
    }


    @Test
    public void testNonAsciiNotToken() {
        for (int i = 128; i < 256; i++) {
            Assert.assertFalse("Character [" + i + "]", HttpParser.isToken(i));
        }
    }


    @Test
    public void testNonAsciiNotRequestTarget() {
        HttpParser httpParser = new HttpParser(null, null);
        for (int i = 128; i < 256; i++) {
            Assert.assertTrue("Character [" + i + "]", httpParser.isNotRequestTargetRelaxed(i));
            Assert.assertFalse("Character [" + i + "]", httpParser.isAbsolutePathRelaxed(i));
            Assert.assertFalse("Character [" + i + "]", httpParser.isQueryRelaxed(i));
        }
    }
}
