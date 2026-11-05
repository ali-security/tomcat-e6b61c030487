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

import java.io.File;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.startup.Tomcat;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * The HTTP/2 half of the fix for the SNI / protocol host name mismatch. A client that completes the TLS handshake for
 * one virtual host must not be able to have the request processed as if it had been made to a different virtual host by
 * providing a different name in the <code>:authority</code> pseudo header or the <code>host</code> header.
 */
public class TestHttp2Sni extends Http2TestBase {

    /*
     * Exploit: TLS handshake for [localhost] then a request for [foobar] via the :authority pseudo header. Both host
     * names have their own SSLHostConfig so the request must be rejected.
     */
    @Test
    public void testAuthorityDoesNotMatchSni() throws Exception {
        doSniConnect("localhost", true);

        sendGetRequestWithAuthority(3, "foobar");

        parser.readFrame();

        String trace = output.getTrace();
        Assert.assertTrue(trace, trace.contains("0-Goaway-[1]-[9]"));
    }


    /*
     * As above but using the host header rather than the :authority pseudo header.
     */
    @Test
    public void testHostHeaderDoesNotMatchSni() throws Exception {
        doSniConnect("localhost", true);

        List<Header> headers = new ArrayList<>(4);
        headers.add(new Header(":method", "GET"));
        headers.add(new Header(":scheme", "https"));
        headers.add(new Header(":path", "/simple"));
        headers.add(new Header("host", "foobar"));

        sendGetRequest(3, headers);

        parser.readFrame();

        String trace = output.getTrace();
        Assert.assertTrue(trace, trace.contains("0-Goaway-[1]-[9]"));
    }


    /*
     * TLS handshake for a host name without its own SSLHostConfig (so the default is used) then a request for an upper
     * case form of [foobar], which has its own SSLHostConfig. Host names are case insensitive so this must be rejected.
     * Without the lower case lookup, [FooBar] also resolved to the default SSLHostConfig and the request was allowed.
     */
    @Test
    public void testAuthorityDoesNotMatchSniMixedCase() throws Exception {
        doSniConnect("other", true);

        sendGetRequestWithAuthority(3, "FooBar");

        parser.readFrame();

        String trace = output.getTrace();
        Assert.assertTrue(trace, trace.contains("0-Goaway-[1]-[9]"));
    }


    /*
     * Control: the host name in the request matches the host name used for the TLS handshake so the request is
     * processed as normal.
     */
    @Test
    public void testAuthorityMatchesSni() throws Exception {
        doSniConnect("localhost", true);

        sendGetRequestWithAuthority(3, "localhost:" + getPort());

        parser.readFrame();
        parser.readFrame();

        String trace = output.getTrace();
        Assert.assertTrue(trace, trace.contains("3-Header-[:status]-[200]"));
    }


    /*
     * Control: with strictSni disabled the mismatch is not checked and the request is processed as it was before the
     * fix for CVE-2025-66614.
     */
    @Test
    public void testAuthorityDoesNotMatchSniNotStrict() throws Exception {
        doSniConnect("localhost", false);

        sendGetRequestWithAuthority(3, "foobar");

        parser.readFrame();
        parser.readFrame();

        String trace = output.getTrace();
        Assert.assertTrue(trace, trace.contains("3-Header-[:status]-[200]"));
    }


    private void sendGetRequestWithAuthority(int streamId, String authority) throws Exception {
        List<Header> headers = new ArrayList<>(4);
        headers.add(new Header(":method", "GET"));
        headers.add(new Header(":scheme", "https"));
        headers.add(new Header(":path", "/simple"));
        headers.add(new Header(":authority", authority));

        sendGetRequest(streamId, headers);
    }


    private void sendGetRequest(int streamId, List<Header> headers) throws Exception {
        byte[] headersFrameHeader = new byte[9];
        ByteBuffer headersPayload = ByteBuffer.allocate(128);

        buildGetRequest(headersFrameHeader, headersPayload, null, headers, streamId);

        writeFrame(headersFrameHeader, headersPayload);
    }


    private void doSniConnect(String sniHostName, boolean strictSni) throws Exception {
        enableHttp2(200, true);

        Tomcat tomcat = getTomcatInstance();
        Assert.assertTrue(tomcat.getConnector().setProperty("strictSni", Boolean.toString(strictSni)));

        // Each of these host names has its own SSLHostConfig
        addSslHostConfig(tomcat, "localhost");
        addSslHostConfig(tomcat, "foobar");

        configureAndStartWebApplication();

        openClientConnection(true, sniHostName);
        doHttpUpgrade();
        sendClientPreface();
        validateHttp2InitialResponse();
    }


    private static void addSslHostConfig(Tomcat tomcat, String hostName) {
        SSLHostConfig sslHostConfig = new SSLHostConfig();
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, Type.UNDEFINED);
        sslHostConfig.addCertificate(certificate);
        certificate.setCertificateKeystoreFile(new File(TesterSupport.LOCALHOST_RSA_JKS).getAbsolutePath());
        certificate.setCertificateKeystorePassword(TesterSupport.JKS_PASS);
        sslHostConfig.setHostName(hostName);
        tomcat.getConnector().addSslHostConfig(sslHostConfig);
    }
}
