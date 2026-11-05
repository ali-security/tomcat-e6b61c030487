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

import org.junit.Assert;
import org.junit.Test;

public class TestConnectionSettings {

    private static final String CONNECTION_ID = "[test]";

    private static final long TEST_MAX_CONCURRENT_STREAMS = 100;
    private static final int TEST_INITIAL_WINDOW_SIZE = 1024;


    /**
     * Without {@code force} a new local setting only takes effect once the client has acknowledged the
     * {@code SETTINGS} frame. Until then the most generous of the current and the pending value applies.
     */
    @Test
    public void testMaxConcurrentStreamsWithoutForce() {
        ConnectionSettingsLocal settings = new ConnectionSettingsLocal(CONNECTION_ID);

        Assert.assertEquals(ConnectionSettingsBase.UNLIMITED, settings.getMaxConcurrentStreams());

        settings.set(Setting.MAX_CONCURRENT_STREAMS, TEST_MAX_CONCURRENT_STREAMS);

        // Not forced so the default (unlimited) still applies
        Assert.assertEquals(ConnectionSettingsBase.UNLIMITED, settings.getMaxConcurrentStreams());

        settings.getSettingsFrameForPending();
        Assert.assertTrue(settings.ack());

        // The ACK moves the pending value to the current value
        Assert.assertEquals(TEST_MAX_CONCURRENT_STREAMS, settings.getMaxConcurrentStreams());
    }


    /**
     * With {@code force} the new local setting takes effect immediately so a client that never acknowledges the
     * {@code SETTINGS} frame cannot ignore the limit.
     */
    @Test
    public void testMaxConcurrentStreamsWithForce() {
        ConnectionSettingsLocal settings = new ConnectionSettingsLocal(CONNECTION_ID);

        settings.set(Setting.MAX_CONCURRENT_STREAMS, TEST_MAX_CONCURRENT_STREAMS, true);

        // Forced so the limit applies before the SETTINGS frame has even been sent
        Assert.assertEquals(TEST_MAX_CONCURRENT_STREAMS, settings.getMaxConcurrentStreams());

        // The setting must still be sent to the client
        byte[] settingsFrame = settings.getSettingsFrameForPending();
        Assert.assertEquals(9 + 6, settingsFrame.length);
        Assert.assertEquals(Setting.MAX_CONCURRENT_STREAMS.getId(), ByteUtil.getTwoBytes(settingsFrame, 9));
        Assert.assertEquals(TEST_MAX_CONCURRENT_STREAMS, ByteUtil.getFourBytes(settingsFrame, 11));

        // And an ACK is still expected
        Assert.assertTrue(settings.ack());

        Assert.assertEquals(TEST_MAX_CONCURRENT_STREAMS, settings.getMaxConcurrentStreams());
    }


    @Test
    public void testInitialWindowSizeWithoutForce() {
        ConnectionSettingsLocal settings = new ConnectionSettingsLocal(CONNECTION_ID);

        Assert.assertEquals(ConnectionSettingsBase.DEFAULT_INITIAL_WINDOW_SIZE, settings.getInitialWindowSize());

        settings.set(Setting.INITIAL_WINDOW_SIZE, TEST_INITIAL_WINDOW_SIZE);

        // Not forced so the default still applies
        Assert.assertEquals(ConnectionSettingsBase.DEFAULT_INITIAL_WINDOW_SIZE, settings.getInitialWindowSize());

        settings.getSettingsFrameForPending();
        Assert.assertTrue(settings.ack());

        Assert.assertEquals(TEST_INITIAL_WINDOW_SIZE, settings.getInitialWindowSize());
    }


    @Test
    public void testInitialWindowSizeWithForce() {
        ConnectionSettingsLocal settings = new ConnectionSettingsLocal(CONNECTION_ID);

        settings.set(Setting.INITIAL_WINDOW_SIZE, TEST_INITIAL_WINDOW_SIZE, true);

        // Forced so the smaller window applies immediately
        Assert.assertEquals(TEST_INITIAL_WINDOW_SIZE, settings.getInitialWindowSize());

        settings.getSettingsFrameForPending();
        Assert.assertTrue(settings.ack());

        Assert.assertEquals(TEST_INITIAL_WINDOW_SIZE, settings.getInitialWindowSize());
    }


    /**
     * A forced setting that matches the current value is a no-op. There is nothing to send so nothing to ACK.
     */
    @Test
    public void testForceWithUnchangedValue() {
        ConnectionSettingsLocal settings = new ConnectionSettingsLocal(CONNECTION_ID);

        settings.set(Setting.INITIAL_WINDOW_SIZE, ConnectionSettingsBase.DEFAULT_INITIAL_WINDOW_SIZE, true);

        Assert.assertEquals(ConnectionSettingsBase.DEFAULT_INITIAL_WINDOW_SIZE, settings.getInitialWindowSize());

        byte[] settingsFrame = settings.getSettingsFrameForPending();
        Assert.assertEquals(9, settingsFrame.length);
    }


    /**
     * Remote settings are dictated by the client so they always apply immediately, with or without {@code force}.
     */
    @Test
    public void testRemoteSettingsAlwaysApplyImmediately() throws Exception {
        ConnectionSettingsRemote settings = new ConnectionSettingsRemote(CONNECTION_ID);

        settings.set(Setting.MAX_CONCURRENT_STREAMS, TEST_MAX_CONCURRENT_STREAMS);
        Assert.assertEquals(TEST_MAX_CONCURRENT_STREAMS, settings.getMaxConcurrentStreams());

        settings.set(Setting.INITIAL_WINDOW_SIZE, TEST_INITIAL_WINDOW_SIZE, true);
        Assert.assertEquals(TEST_INITIAL_WINDOW_SIZE, settings.getInitialWindowSize());
    }
}
