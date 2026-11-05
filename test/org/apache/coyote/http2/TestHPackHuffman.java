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
package org.apache.coyote.http2;

import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;


public class TestHPackHuffman {

    /*
     * This specific String exposed an edge case that triggered an unexpected HPACK parsing failure.
     */
    @Test
    public void testValueLeftBrace() throws Exception {
        doTestRoundTrip("x-value{");
    }


    /*
     * Like '{', the Huffman code for 0xF9 is a run of 1 bits terminated by a single 0 bit. The 'a' characters ensure
     * that the Huffman encoded form is not longer than the original (else it would not be Huffman encoded).
     */
    @Test
    public void testValueTrailingU00F9() throws Exception {
        doTestRoundTrip("x-valueaaaaaù");
    }


    private void doTestRoundTrip(String data) throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(16);
        Assert.assertTrue("Value was not Huffman encoded", HPackHuffman.encode(buf, data, false));

        buf.flip();
        // Remove the header byte (in Tomcat this is parsed before the bytes are passed to the HPACK decoder)
        buf.get();

        StringBuilder target = new StringBuilder();
        HPackHuffman.decode(buf, buf.remaining(), target);

        Assert.assertEquals("Value changed after encode/decode roundtrip", data, target.toString());
    }
}
