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
package org.apache.tomcat.util.net;

import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests that the flag used by {@link SecureNioChannel} to track a pending TLS handshake wrap is correctly cleared so
 * that stale state cannot cause spurious TLS connection failures.
 */
public class TestSecureNioChannel {

    @Test
    public void testResetClearsNeedHandshakeWrap() throws Exception {
        SecureNioChannel channel =
                new SecureNioChannel(new SocketBufferHandler(1024, 1024, false), new NioEndpoint());

        // Simulate a channel that is returned to the cache while a handshake wrap is still pending
        channel.needHandshakeWrap = true;

        try (SocketChannel sc = SocketChannel.open()) {
            // Re-use the cached channel for a new connection
            channel.reset(sc, null);
        }

        Assert.assertFalse("needHandshakeWrap must not leak into the next connection", channel.needHandshakeWrap);
        Assert.assertFalse(channel.handshakeComplete);
        Assert.assertFalse(channel.sniComplete);
    }


    @Test
    public void testGatheringWriteClearsNeedHandshakeWrap() throws Exception {
        SecureNioChannel channel =
                new SecureNioChannel(new SocketBufferHandler(1024, 1024, false), new NioEndpoint()) {
                    @Override
                    protected boolean flush(ByteBuffer buf) {
                        // No network - discard everything
                        buf.position(buf.limit());
                        return true;
                    }
                };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(true);
        channel.sslEngine = sslEngine;

        // A handshake wrap was deferred because there was outbound data pending
        channel.needHandshakeWrap = true;

        ByteBuffer[] srcs = new ByteBuffer[] { ByteBuffer.allocate(0), ByteBuffer.allocate(0) };
        channel.write(srcs, 0, srcs.length);

        // The call to wrap() will have included any required handshake data
        Assert.assertFalse("needHandshakeWrap must be cleared once wrap() has been called", channel.needHandshakeWrap);
    }


    @Test
    public void testSingleWriteClearsNeedHandshakeWrap() throws Exception {
        SecureNioChannel channel =
                new SecureNioChannel(new SocketBufferHandler(1024, 1024, false), new NioEndpoint()) {
                    @Override
                    protected boolean flush(ByteBuffer buf) {
                        // No network - discard everything
                        buf.position(buf.limit());
                        return true;
                    }
                };

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, null, null);
        SSLEngine sslEngine = sslContext.createSSLEngine();
        sslEngine.setUseClientMode(true);
        channel.sslEngine = sslEngine;

        channel.needHandshakeWrap = true;

        ByteBuffer src = ByteBuffer.wrap(new byte[] { 'a' });
        channel.write(src);

        Assert.assertFalse("needHandshakeWrap must be cleared once wrap() has been called", channel.needHandshakeWrap);
    }
}
