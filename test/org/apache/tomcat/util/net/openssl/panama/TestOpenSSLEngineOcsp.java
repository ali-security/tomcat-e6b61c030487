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
package org.apache.tomcat.util.net.openssl.panama;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.core.OpenSSLLifecycleListener;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * Checks that an OCSP check performed by the OpenSSL FFM engine fails, rather
 * than soft-fails, when the OCSP responder is not able to provide a usable
 * response. Without this, a client certificate that has been revoked would be
 * accepted if the OCSP responder could not be reached or returned an error.
 * <p>
 * Also checks that OCSP responses are only accepted if they are signed by a
 * trusted responder, match the nonce sent in the request and are fresh, and
 * that the OCSP request is subject to a timeout. Without this, an attacker
 * able to tamper with, or replay, OCSP responses could have a revoked
 * certificate accepted.
 * <p>
 * The test sources are compiled for Java 11 so all access to the FFM API and to
 * the FFM based classes is via reflection.
 */
public class TestOpenSSLEngineOcsp {

    // Constants from OpenSSL's x509_vfy.h and ocsp.h
    private static final int X509_V_OK = 0;
    private static final int X509_V_ERR_UNABLE_TO_GET_CRL = 3;
    private static final int X509_V_ERR_APPLICATION_VERIFICATION = 50;
    private static final int X509_V_ERR_OCSP_RESP_INVALID = 96;
    private static final int X509_V_ERR_OCSP_SIGNATURE_FAILURE = 97;
    private static final int X509_V_ERR_OCSP_NOT_YET_VALID = 98;
    private static final int X509_V_ERR_OCSP_HAS_EXPIRED = 99;
    private static final int V_OCSP_CERTSTATUS_GOOD = 0;
    private static final int V_OCSP_CERTSTATUS_REVOKED = 1;
    private static final int V_OCSP_CERTSTATUS_UNKNOWN = 2;
    private static final int OCSP_RESPONSE_STATUS_SUCCESSFUL = 0;
    private static final int MBSTRING_ASC = 0x1001;

    private static final int DEFAULT_OCSP_TIMEOUT = 15000;
    private static final int SHORT_OCSP_TIMEOUT = 1000;
    private static final long SLOW_RESPONDER_DELAY = 6000;

    private static final long ONE_DAY = 24 * 60 * 60;

    private static final String OPENSSL_H = "org.apache.tomcat.util.openssl.openssl_h";
    private static final String ENGINE = "org.apache.tomcat.util.net.openssl.panama.OpenSSLEngine";

    private static final String HOST = "127.0.0.1";

    private static Class<?> memorySegmentClass;
    private static Class<?> arenaClass;
    private static Class<?> opensslH;
    private static Object nullSegment;
    private static Object addressLayout;
    private static Object byteLayout;
    private static Object classArena;

    private static MethodHandle x509StoreCtxNew;
    private static MethodHandle x509StoreCtxFree;
    private static MethodHandle x509StoreCtxSetExData;
    private static MethodHandle x509StoreCtxInit;

    // Used to create a test PKI and to create OCSP responses
    private static MethodHandle x509New;
    private static MethodHandle x509SetVersion;
    private static MethodHandle x509GetSerialNumber;
    private static MethodHandle asn1IntegerSet;
    private static MethodHandle x509GetmNotBefore;
    private static MethodHandle x509GetmNotAfter;
    private static MethodHandle x509GmtimeAdj;
    private static MethodHandle x509SetPubkey;
    private static MethodHandle x509GetSubjectName;
    private static MethodHandle x509NameAddEntryByTxt;
    private static MethodHandle x509SetIssuerName;
    private static MethodHandle x509Sign;
    private static MethodHandle evpSha256;
    private static MethodHandle d2iAutoPrivateKey;
    private static MethodHandle x509StoreNew;
    private static MethodHandle x509StoreAddCert;
    private static MethodHandle x509StoreFree;
    private static MethodHandle asn1TimeFree;
    private static MethodHandle d2iOcspRequest;
    private static MethodHandle ocspBasicRespNew;
    private static MethodHandle ocspBasicAdd1Status;
    private static MethodHandle ocspCopyNonce;
    private static MethodHandle ocspBasicAdd1Nonce;
    private static MethodHandle ocspBasicSign;
    private static MethodHandle ocspResponseCreate;
    private static MethodHandle i2dOcspResponse;

    private static Object leaf;
    private static Object issuer;

    // Test PKI with keys available so OCSP responses can be signed
    private static Object caCert;
    private static Object caKey;
    private static Object ocspLeafCert;
    private static Object ocspLeafKey;
    private static Object rogueCaCert;
    private static Object rogueCaKey;
    private static Object trustStore;

    private static ExecutorService ocspResponderExecutor;
    private static HttpServer ocspResponder;

    private Object sslCtx;
    private Object engineState;
    private Object x509ctx;


    @BeforeClass
    public static void setUp() throws Throwable {
        Assume.assumeTrue("FFM requires Java 22 or later", JreCompat.isJre22Available());
        @SuppressWarnings("unused")
        OpenSSLLifecycleListener listener = new OpenSSLLifecycleListener();
        Assume.assumeTrue("OpenSSL is not available", OpenSSLLifecycleListener.isAvailable());

        memorySegmentClass = Class.forName("java.lang.foreign.MemorySegment");
        arenaClass = Class.forName("java.lang.foreign.Arena");
        opensslH = Class.forName(OPENSSL_H);
        nullSegment = memorySegmentClass.getField("NULL").get(null);
        Class<?> valueLayoutClass = Class.forName("java.lang.foreign.ValueLayout");
        addressLayout = valueLayoutClass.getField("ADDRESS").get(null);
        byteLayout = valueLayoutClass.getField("JAVA_BYTE").get(null);
        Object intLayout = valueLayoutClass.getField("JAVA_INT").get(null);
        Object longLayout = opensslH.getField("C_LONG").get(null);
        classArena = arenaClass.getMethod("ofAuto").invoke(null);

        // Functions not exposed by openssl_h
        x509StoreCtxNew = downcall("X509_STORE_CTX_new", addressLayout);
        x509StoreCtxFree = downcall("X509_STORE_CTX_free", null, addressLayout);
        x509StoreCtxSetExData = downcall("X509_STORE_CTX_set_ex_data", intLayout,
                addressLayout, intLayout, addressLayout);
        x509StoreCtxInit = downcall("X509_STORE_CTX_init", intLayout,
                addressLayout, addressLayout, addressLayout, addressLayout);
        x509New = downcall("X509_new", addressLayout);
        x509SetVersion = downcall("X509_set_version", intLayout, addressLayout, longLayout);
        x509GetSerialNumber = downcall("X509_get_serialNumber", addressLayout, addressLayout);
        asn1IntegerSet = downcall("ASN1_INTEGER_set", intLayout, addressLayout, longLayout);
        x509GetmNotBefore = downcall("X509_getm_notBefore", addressLayout, addressLayout);
        x509GetmNotAfter = downcall("X509_getm_notAfter", addressLayout, addressLayout);
        x509GmtimeAdj = downcall("X509_gmtime_adj", addressLayout, addressLayout, longLayout);
        x509SetPubkey = downcall("X509_set_pubkey", intLayout, addressLayout, addressLayout);
        x509GetSubjectName = downcall("X509_get_subject_name", addressLayout, addressLayout);
        x509NameAddEntryByTxt = downcall("X509_NAME_add_entry_by_txt", intLayout, addressLayout,
                addressLayout, intLayout, addressLayout, intLayout, intLayout, intLayout);
        x509SetIssuerName = downcall("X509_set_issuer_name", intLayout, addressLayout, addressLayout);
        x509Sign = downcall("X509_sign", intLayout, addressLayout, addressLayout, addressLayout);
        evpSha256 = downcall("EVP_sha256", addressLayout);
        d2iAutoPrivateKey = downcall("d2i_AutoPrivateKey", addressLayout,
                addressLayout, addressLayout, longLayout);
        x509StoreNew = downcall("X509_STORE_new", addressLayout);
        x509StoreAddCert = downcall("X509_STORE_add_cert", intLayout, addressLayout, addressLayout);
        x509StoreFree = downcall("X509_STORE_free", null, addressLayout);
        asn1TimeFree = downcall("ASN1_TIME_free", null, addressLayout);
        d2iOcspRequest = downcall("d2i_OCSP_REQUEST", addressLayout,
                addressLayout, addressLayout, longLayout);
        ocspBasicRespNew = downcall("OCSP_BASICRESP_new", addressLayout);
        ocspBasicAdd1Status = downcall("OCSP_basic_add1_status", addressLayout, addressLayout,
                addressLayout, intLayout, intLayout, addressLayout, addressLayout, addressLayout);
        ocspCopyNonce = downcall("OCSP_copy_nonce", intLayout, addressLayout, addressLayout);
        ocspBasicAdd1Nonce = downcall("OCSP_basic_add1_nonce", intLayout,
                addressLayout, addressLayout, intLayout);
        ocspBasicSign = downcall("OCSP_basic_sign", intLayout, addressLayout,
                addressLayout, addressLayout, addressLayout, addressLayout, longLayout);
        ocspResponseCreate = downcall("OCSP_response_create", addressLayout, intLayout, addressLayout);
        i2dOcspResponse = downcall("i2d_OCSP_RESPONSE", intLayout, addressLayout, addressLayout);

        // Client certificate and its issuer
        KeyStore ks = KeyStore.getInstance("JKS");
        try (InputStream is = new FileInputStream(new File(TesterSupport.CLIENT_JKS))) {
            ks.load(is, TesterSupport.JKS_PASS.toCharArray());
        }
        Certificate[] chain = ks.getCertificateChain(TesterSupport.CLIENT_ALIAS);
        Assert.assertNotNull(chain);
        Assert.assertEquals(2, chain.length);
        leaf = toNativeX509(chain[0]);
        issuer = toNativeX509(chain[1]);

        // Test PKI: a trusted CA, a certificate it issued and an untrusted (rogue) CA
        Object[] ca = createCertificate("Tomcat OCSP Test CA", 1, null, null);
        caCert = ca[0];
        caKey = ca[1];
        Object[] ocspLeaf = createCertificate("Tomcat OCSP Test Client", 2, caCert, caKey);
        ocspLeafCert = ocspLeaf[0];
        ocspLeafKey = ocspLeaf[1];
        // Same subject as the trusted CA but with a different key
        Object[] rogueCa = createCertificate("Tomcat OCSP Test CA", 1, null, null);
        rogueCaCert = rogueCa[0];
        rogueCaKey = rogueCa[1];
        trustStore = x509StoreNew.invokeWithArguments();
        Assert.assertNotEquals(nullSegment, trustStore);
        Assert.assertEquals(Integer.valueOf(1), x509StoreAddCert.invokeWithArguments(trustStore, caCert));

        // OCSP responder
        ocspResponderExecutor = Executors.newCachedThreadPool();
        ocspResponder = HttpServer.create(new InetSocketAddress(HOST, 0), 0);
        ocspResponder.setExecutor(ocspResponderExecutor);
        // Responses that are never usable
        ocspResponder.createContext("/error", exchange -> respond(exchange, 500, new byte[0]));
        ocspResponder.createContext("/invalid", exchange -> respond(exchange, 200,
                "This is not an OCSP response".getBytes(StandardCharsets.ISO_8859_1)));
        ocspResponder.createContext("/large", exchange -> respond(exchange, 200, new byte[200 * 1024]));
        ocspResponder.createContext("/slow", exchange -> {
            try {
                Thread.sleep(SLOW_RESPONDER_DELAY);
            } catch (InterruptedException e) {
                // Test is complete
            }
            respond(exchange, 500, new byte[0]);
        });
        // Valid responses
        ocspResponder.createContext("/good", exchange -> respondOcsp(exchange,
                new ResponseSpec(V_OCSP_CERTSTATUS_GOOD, caCert, caKey)));
        ocspResponder.createContext("/revoked", exchange -> respondOcsp(exchange,
                new ResponseSpec(V_OCSP_CERTSTATUS_REVOKED, caCert, caKey)));
        // Forged, replayed and stale responses
        ocspResponder.createContext("/signed-by-rogue-ca", exchange -> respondOcsp(exchange,
                new ResponseSpec(V_OCSP_CERTSTATUS_GOOD, rogueCaCert, rogueCaKey)));
        ocspResponder.createContext("/signed-by-certificate", exchange -> respondOcsp(exchange,
                new ResponseSpec(V_OCSP_CERTSTATUS_GOOD, ocspLeafCert, ocspLeafKey)));
        ocspResponder.createContext("/nonce-mismatch", exchange -> {
            ResponseSpec spec = new ResponseSpec(V_OCSP_CERTSTATUS_GOOD, caCert, caKey);
            spec.copyNonce = false;
            respondOcsp(exchange, spec);
        });
        ocspResponder.createContext("/other-certificate", exchange -> {
            ResponseSpec spec = new ResponseSpec(V_OCSP_CERTSTATUS_GOOD, caCert, caKey);
            spec.statusCert = caCert;
            respondOcsp(exchange, spec);
        });
        ocspResponder.createContext("/expired", exchange -> {
            ResponseSpec spec = new ResponseSpec(V_OCSP_CERTSTATUS_GOOD, caCert, caKey);
            spec.thisUpdateOffset = -2 * ONE_DAY;
            spec.nextUpdateOffset = Long.valueOf(-ONE_DAY);
            respondOcsp(exchange, spec);
        });
        ocspResponder.createContext("/not-yet-valid", exchange -> {
            ResponseSpec spec = new ResponseSpec(V_OCSP_CERTSTATUS_GOOD, caCert, caKey);
            spec.thisUpdateOffset = ONE_DAY;
            spec.nextUpdateOffset = Long.valueOf(2 * ONE_DAY);
            respondOcsp(exchange, spec);
        });
        ocspResponder.createContext("/too-old", exchange -> {
            ResponseSpec spec = new ResponseSpec(V_OCSP_CERTSTATUS_GOOD, caCert, caKey);
            spec.thisUpdateOffset = -ONE_DAY;
            spec.nextUpdateOffset = null;
            respondOcsp(exchange, spec);
        });
        ocspResponder.start();
    }


    @AfterClass
    public static void tearDown() throws Throwable {
        if (ocspResponder != null) {
            ocspResponder.stop(0);
            ocspResponder = null;
        }
        if (ocspResponderExecutor != null) {
            ocspResponderExecutor.shutdownNow();
            ocspResponderExecutor = null;
        }
        if (leaf != null) {
            call("X509_free", leaf);
            leaf = null;
        }
        if (issuer != null) {
            call("X509_free", issuer);
            issuer = null;
        }
        if (trustStore != null) {
            x509StoreFree.invokeWithArguments(trustStore);
            trustStore = null;
        }
        for (Object x509 : new Object[] { caCert, ocspLeafCert, rogueCaCert }) {
            if (x509 != null) {
                call("X509_free", x509);
            }
        }
        caCert = null;
        ocspLeafCert = null;
        rogueCaCert = null;
        for (Object key : new Object[] { caKey, ocspLeafKey, rogueCaKey }) {
            if (key != null) {
                call("EVP_PKEY_free", key);
            }
        }
        caKey = null;
        ocspLeafKey = null;
        rogueCaKey = null;
    }


    @After
    public void releaseVerificationContext() throws Throwable {
        if (x509ctx != null) {
            x509StoreCtxFree.invokeWithArguments(x509ctx);
            x509ctx = null;
        }
        if (engineState != null) {
            // Frees the SSL and the BIO
            ((Runnable) engineState).run();
            engineState = null;
        }
        if (sslCtx != null) {
            call("SSL_CTX_free", sslCtx);
            sslCtx = null;
        }
    }


    @Test
    public void testResponderHttpError() throws Throwable {
        doTestOcspFailure(responderUrl("/error"), X509_V_ERR_UNABLE_TO_GET_CRL);
    }


    @Test
    public void testResponderResponseTooLarge() throws Throwable {
        doTestOcspFailure(responderUrl("/large"), X509_V_ERR_UNABLE_TO_GET_CRL);
    }


    @Test
    public void testResponderUnavailable() throws Throwable {
        int port;
        try (ServerSocket s = new ServerSocket()) {
            s.bind(new InetSocketAddress(HOST, 0));
            port = s.getLocalPort();
        }
        // Nothing is listening on the port anymore
        doTestOcspFailure(new URL("http://" + HOST + ":" + port + "/"), X509_V_ERR_UNABLE_TO_GET_CRL);
    }


    @Test
    public void testResponderInvalidResponse() throws Throwable {
        doTestOcspFailure(responderUrl("/invalid"), X509_V_ERR_APPLICATION_VERIFICATION);
    }


    @Test
    public void testNoOcspCheck() throws Throwable {
        // Control: the verification is not rejected when OCSP is disabled
        createVerificationContext(true);
        call("X509_STORE_CTX_set_error", x509ctx, Integer.valueOf(X509_V_ERR_UNABLE_TO_GET_CRL));
        Assert.assertEquals(1, verify());
    }


    @Test
    public void testResponderTimeout() throws Throwable {
        createVerificationContext(false, SHORT_OCSP_TIMEOUT, null);

        long start = System.nanoTime();
        Assert.assertEquals(V_OCSP_CERTSTATUS_UNKNOWN, processOCSPRequest(responderUrl("/slow"), issuer, leaf));
        long durationMillis = (System.nanoTime() - start) / 1000000;
        Assert.assertEquals(X509_V_ERR_UNABLE_TO_GET_CRL, getError());
        Assert.assertTrue("The OCSP request took [" + durationMillis + "] ms and did not time out",
                durationMillis < SLOW_RESPONDER_DELAY - 2000);
        Assert.assertEquals("Client certificate accepted although the OCSP check failed", 0, verify());
    }


    @Test
    public void testResponseGood() throws Throwable {
        // Control: a fresh response signed by the CA that issued the certificate is accepted
        createSignedResponseVerificationContext();

        Assert.assertEquals(V_OCSP_CERTSTATUS_GOOD,
                processOCSPRequest(responderUrl("/good"), caCert, ocspLeafCert));
        Assert.assertEquals(X509_V_OK, getError());
    }


    @Test
    public void testResponseRevoked() throws Throwable {
        // Control: a fresh response signed by the CA that issued the certificate is accepted
        createSignedResponseVerificationContext();

        Assert.assertEquals(V_OCSP_CERTSTATUS_REVOKED,
                processOCSPRequest(responderUrl("/revoked"), caCert, ocspLeafCert));
    }


    @Test
    public void testResponseSignedByUntrustedResponder() throws Throwable {
        // Forged response claiming the certificate is good, signed by a CA that is not trusted
        doTestSignedOcspFailure("/signed-by-rogue-ca", X509_V_ERR_OCSP_SIGNATURE_FAILURE);
    }


    @Test
    public void testResponseSignedByCertificateKey() throws Throwable {
        // Forged response claiming the certificate is good, signed with the key of the certificate
        // being checked. The certificate is trusted but it is not authorised to sign OCSP responses.
        doTestSignedOcspFailure("/signed-by-certificate", X509_V_ERR_OCSP_SIGNATURE_FAILURE);
    }


    @Test
    public void testResponseNonceMismatch() throws Throwable {
        // Replayed response - the nonce does not match the one sent in the request
        doTestSignedOcspFailure("/nonce-mismatch", X509_V_ERR_OCSP_RESP_INVALID);
    }


    @Test
    public void testResponseForOtherCertificate() throws Throwable {
        // The response does not include a status for the certificate being checked
        doTestSignedOcspFailure("/other-certificate", X509_V_ERR_OCSP_RESP_INVALID);
    }


    @Test
    public void testResponseExpired() throws Throwable {
        // nextUpdate is in the past
        doTestSignedOcspFailure("/expired", X509_V_ERR_OCSP_NOT_YET_VALID);
    }


    @Test
    public void testResponseNotYetValid() throws Throwable {
        // thisUpdate is in the future
        doTestSignedOcspFailure("/not-yet-valid", X509_V_ERR_OCSP_NOT_YET_VALID);
    }


    @Test
    public void testResponseTooOld() throws Throwable {
        // No nextUpdate and thisUpdate is older than the maximum allowed age
        doTestSignedOcspFailure("/too-old", X509_V_ERR_OCSP_HAS_EXPIRED);
    }


    private void doTestOcspFailure(URL url, int expectedError) throws Throwable {
        createVerificationContext(false);

        Assert.assertEquals(V_OCSP_CERTSTATUS_UNKNOWN, processOCSPRequest(url, issuer, leaf));
        Assert.assertEquals(expectedError, getError());

        /*
         * The verification context has no current certificate so the OCSP
         * processing in the callback returns V_OCSP_CERTSTATUS_UNKNOWN and
         * leaves the error set by processOCSPRequest() above unchanged. This is
         * the state the callback sees after a failed OCSP request. The
         * certificate must be rejected.
         */
        Assert.assertEquals("Client certificate accepted although the OCSP check failed", 0, verify());
    }


    private void doTestSignedOcspFailure(String path, int expectedError) throws Throwable {
        createSignedResponseVerificationContext();

        Assert.assertEquals("OCSP response from [" + path + "] was accepted", V_OCSP_CERTSTATUS_UNKNOWN,
                processOCSPRequest(responderUrl(path), caCert, ocspLeafCert));
        Assert.assertEquals(expectedError, getError());

        // See doTestOcspFailure()
        Assert.assertEquals("Client certificate accepted although the OCSP response was not valid", 0, verify());
    }


    private void createVerificationContext(boolean noOcspCheck) throws Throwable {
        createVerificationContext(noOcspCheck, DEFAULT_OCSP_TIMEOUT, null);
    }


    private void createSignedResponseVerificationContext() throws Throwable {
        // The OCSP response signer is validated using the trust store of the verification context
        createVerificationContext(false, DEFAULT_OCSP_TIMEOUT, trustStore);
    }


    private void createVerificationContext(boolean noOcspCheck, int ocspTimeout, Object store) throws Throwable {
        x509ctx = x509StoreCtxNew.invokeWithArguments();
        Assert.assertNotEquals(nullSegment, x509ctx);
        if (store != null) {
            Assert.assertEquals(Integer.valueOf(1),
                    x509StoreCtxInit.invokeWithArguments(x509ctx, store, nullSegment, nullSegment));
        }

        sslCtx = call("SSL_CTX_new", call("TLS_server_method"));
        Object ssl = call("SSL_new", sslCtx);
        Object networkBIO = call("BIO_new", call("BIO_s_mem"));

        Class<?> engineStateClass = Class.forName(ENGINE + "$EngineState");
        Constructor<?> constructor = engineStateClass.getDeclaredConstructor(memorySegmentClass,
                memorySegmentClass, int.class, boolean.class, int.class, int.class);
        constructor.setAccessible(true);
        engineState = constructor.newInstance(ssl, networkBIO, Integer.valueOf(10), Boolean.valueOf(noOcspCheck),
                Integer.valueOf(ocspTimeout), Integer.valueOf(0));

        // Equivalent of client certificate verification "required"
        Field certificateVerifyMode = engineStateClass.getDeclaredField("certificateVerifyMode");
        certificateVerifyMode.setAccessible(true);
        certificateVerifyMode.setInt(engineState, ((Integer) call("SSL_VERIFY_FAIL_IF_NO_PEER_CERT")).intValue());

        // Associate the verification context with the SSL instance
        Object idx = call("SSL_get_ex_data_X509_STORE_CTX_idx");
        Object rc = x509StoreCtxSetExData.invokeWithArguments(x509ctx, idx, ssl);
        Assert.assertEquals(Integer.valueOf(1), rc);
    }


    private int processOCSPRequest(URL url, Object issuerCert, Object cert) throws Exception {
        Class<?> engineStateClass = Class.forName(ENGINE + "$EngineState");
        Method processOCSPRequest = Class.forName(ENGINE).getDeclaredMethod("processOCSPRequest", engineStateClass,
                URL.class, memorySegmentClass, memorySegmentClass, memorySegmentClass, arenaClass);
        processOCSPRequest.setAccessible(true);
        Object localArena = arenaClass.getMethod("ofConfined").invoke(null);
        try {
            return ((Integer) processOCSPRequest.invoke(null, engineState, url, issuerCert, cert, x509ctx,
                    localArena)).intValue();
        } finally {
            ((AutoCloseable) localArena).close();
        }
    }


    private int verify() throws Exception {
        Class<?> verifyCallbackClass = Class.forName(ENGINE + "$VerifyCallback");
        Constructor<?> constructor = verifyCallbackClass.getDeclaredConstructor();
        constructor.setAccessible(true);
        Object verifyCallback = constructor.newInstance();
        Method apply = verifyCallbackClass.getMethod("apply", int.class, memorySegmentClass);
        apply.setAccessible(true);
        return ((Integer) apply.invoke(verifyCallback, Integer.valueOf(1), x509ctx)).intValue();
    }


    private int getError() throws Exception {
        return ((Integer) call("X509_STORE_CTX_get_error", x509ctx)).intValue();
    }


    private static URL responderUrl(String path) throws IOException {
        return new URL("http://" + HOST + ":" + ocspResponder.getAddress().getPort() + path);
    }


    private static void respond(HttpExchange exchange, int status, byte[] body) throws IOException {
        try {
            try (InputStream is = exchange.getRequestBody()) {
                is.readAllBytes();
            }
            exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
            if (body.length > 0) {
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(body);
                }
            }
        } catch (IOException ioe) {
            // The client may stop reading the response early
        } finally {
            exchange.close();
        }
    }


    private static void respondOcsp(HttpExchange exchange, ResponseSpec spec) throws IOException {
        // The request body stream is closed by respond()
        byte[] request = exchange.getRequestBody().readAllBytes();
        byte[] response;
        try {
            response = createOcspResponse(request, spec);
        } catch (Throwable t) {
            t.printStackTrace();
            respond(exchange, 500, new byte[0]);
            return;
        }
        respond(exchange, 200, response);
    }


    /*
     * Creates a DER encoded OCSP response for the provided DER encoded OCSP
     * request.
     */
    private static byte[] createOcspResponse(byte[] request, ResponseSpec spec) throws Throwable {
        Object arena = arenaClass.getMethod("ofConfined").invoke(null);
        Object ocspRequest = nullSegment;
        Object basicResponse = nullSegment;
        Object certId = nullSegment;
        Object ocspResponse = nullSegment;
        Object thisUpdate = nullSegment;
        Object nextUpdate = nullSegment;
        Object revocationTime = nullSegment;
        try {
            Object requestPointer = toPointer(arena, toSegment(arena, request));
            ocspRequest = d2iOcspRequest.invokeWithArguments(nullSegment, requestPointer,
                    Long.valueOf(request.length));
            Assert.assertNotEquals(nullSegment, ocspRequest);

            basicResponse = ocspBasicRespNew.invokeWithArguments();
            certId = call("OCSP_cert_to_id", nullSegment, spec.statusCert, caCert);
            Assert.assertNotEquals(nullSegment, certId);
            thisUpdate = x509GmtimeAdj.invokeWithArguments(nullSegment, Long.valueOf(spec.thisUpdateOffset));
            if (spec.nextUpdateOffset != null) {
                nextUpdate = x509GmtimeAdj.invokeWithArguments(nullSegment, spec.nextUpdateOffset);
            }
            if (spec.certStatus == V_OCSP_CERTSTATUS_REVOKED) {
                revocationTime = x509GmtimeAdj.invokeWithArguments(nullSegment, Long.valueOf(-ONE_DAY));
            }
            Assert.assertNotEquals(nullSegment, ocspBasicAdd1Status.invokeWithArguments(basicResponse, certId,
                    Integer.valueOf(spec.certStatus), Integer.valueOf(-1), revocationTime, thisUpdate, nextUpdate));
            if (spec.copyNonce) {
                Assert.assertTrue(((Integer) ocspCopyNonce.invokeWithArguments(basicResponse, ocspRequest))
                        .intValue() > 0);
            } else {
                // Use a different nonce
                Assert.assertEquals(Integer.valueOf(1),
                        ocspBasicAdd1Nonce.invokeWithArguments(basicResponse, nullSegment, Integer.valueOf(-1)));
            }
            Assert.assertEquals(Integer.valueOf(1), ocspBasicSign.invokeWithArguments(basicResponse,
                    spec.signerCert, spec.signerKey, evpSha256.invokeWithArguments(), nullSegment, Long.valueOf(0)));

            ocspResponse = ocspResponseCreate.invokeWithArguments(Integer.valueOf(OCSP_RESPONSE_STATUS_SUCCESSFUL),
                    basicResponse);
            Assert.assertNotEquals(nullSegment, ocspResponse);
            int length = ((Integer) i2dOcspResponse.invokeWithArguments(ocspResponse, nullSegment)).intValue();
            Assert.assertTrue(length > 0);
            Object buffer = arenaClass.getMethod("allocate", long.class).invoke(arena, Long.valueOf(length));
            Assert.assertEquals(Integer.valueOf(length),
                    i2dOcspResponse.invokeWithArguments(ocspResponse, toPointer(arena, buffer)));
            return (byte[]) memorySegmentClass.getMethod("toArray",
                    Class.forName("java.lang.foreign.ValueLayout$OfByte")).invoke(buffer, byteLayout);
        } finally {
            if (!nullSegment.equals(ocspResponse)) {
                call("OCSP_RESPONSE_free", ocspResponse);
            }
            if (!nullSegment.equals(basicResponse)) {
                call("OCSP_BASICRESP_free", basicResponse);
            }
            if (!nullSegment.equals(certId)) {
                call("OCSP_CERTID_free", certId);
            }
            if (!nullSegment.equals(ocspRequest)) {
                call("OCSP_REQUEST_free", ocspRequest);
            }
            for (Object time : new Object[] { thisUpdate, nextUpdate, revocationTime }) {
                if (!nullSegment.equals(time)) {
                    asn1TimeFree.invokeWithArguments(time);
                }
            }
            ((AutoCloseable) arena).close();
        }
    }


    /*
     * Creates a certificate and its EC private key. If no issuer is provided,
     * the certificate is self-signed.
     */
    private static Object[] createCertificate(String cn, long serial, Object issuerCert, Object issuerKey)
            throws Throwable {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair keyPair = kpg.generateKeyPair();
        byte[] keyDer = keyPair.getPrivate().getEncoded();
        Object key = d2iAutoPrivateKey.invokeWithArguments(nullSegment,
                toPointer(classArena, toSegment(classArena, keyDer)), Long.valueOf(keyDer.length));
        Assert.assertNotEquals(nullSegment, key);

        Object x509 = x509New.invokeWithArguments();
        Assert.assertNotEquals(nullSegment, x509);
        // Version 1 so that a self-signed certificate is a valid root CA without any extensions
        Assert.assertEquals(Integer.valueOf(1), x509SetVersion.invokeWithArguments(x509, Long.valueOf(0)));
        Assert.assertEquals(Integer.valueOf(1), asn1IntegerSet.invokeWithArguments(
                x509GetSerialNumber.invokeWithArguments(x509), Long.valueOf(serial)));
        Assert.assertNotEquals(nullSegment, x509GmtimeAdj.invokeWithArguments(
                x509GetmNotBefore.invokeWithArguments(x509), Long.valueOf(-ONE_DAY)));
        Assert.assertNotEquals(nullSegment, x509GmtimeAdj.invokeWithArguments(
                x509GetmNotAfter.invokeWithArguments(x509), Long.valueOf(ONE_DAY)));
        Assert.assertEquals(Integer.valueOf(1), x509SetPubkey.invokeWithArguments(x509, key));
        Object subject = x509GetSubjectName.invokeWithArguments(x509);
        Object field = arenaClass.getMethod("allocateFrom", String.class).invoke(classArena, "CN");
        Object value = arenaClass.getMethod("allocateFrom", String.class).invoke(classArena, cn);
        Assert.assertEquals(Integer.valueOf(1), x509NameAddEntryByTxt.invokeWithArguments(subject, field,
                Integer.valueOf(MBSTRING_ASC), value, Integer.valueOf(-1), Integer.valueOf(-1), Integer.valueOf(0)));
        Object issuerName = issuerCert == null ? subject : x509GetSubjectName.invokeWithArguments(issuerCert);
        Assert.assertEquals(Integer.valueOf(1), x509SetIssuerName.invokeWithArguments(x509, issuerName));
        Assert.assertTrue(((Integer) x509Sign.invokeWithArguments(x509, issuerKey == null ? key : issuerKey,
                evpSha256.invokeWithArguments())).intValue() > 0);
        return new Object[] { x509, key };
    }


    private static Object toNativeX509(Certificate certificate) throws Exception {
        byte[] der = certificate.getEncoded();
        Object derPointer = toPointer(classArena, toSegment(classArena, der));
        Object x509 = call("d2i_X509", nullSegment, derPointer, Long.valueOf(der.length));
        Assert.assertNotEquals(nullSegment, x509);
        return x509;
    }


    private static Object toSegment(Object arena, byte[] bytes) throws Exception {
        return arenaClass.getMethod("allocateFrom", Class.forName("java.lang.foreign.ValueLayout$OfByte"),
                byte[].class).invoke(arena, byteLayout, bytes);
    }


    private static Object toPointer(Object arena, Object segment) throws Exception {
        return arenaClass.getMethod("allocateFrom", Class.forName("java.lang.foreign.AddressLayout"),
                memorySegmentClass).invoke(arena, addressLayout, segment);
    }


    private static Object call(String name, Object... args) throws Exception {
        for (Method method : opensslH.getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == args.length) {
                return method.invoke(null, args);
            }
        }
        throw new NoSuchMethodException(name);
    }


    private static MethodHandle downcall(String symbol, Object returnLayout, Object... argumentLayouts)
            throws Exception {
        Class<?> memoryLayoutClass = Class.forName("java.lang.foreign.MemoryLayout");
        Class<?> functionDescriptorClass = Class.forName("java.lang.foreign.FunctionDescriptor");
        Class<?> linkerClass = Class.forName("java.lang.foreign.Linker");
        Class<?> linkerOptionClass = Class.forName("java.lang.foreign.Linker$Option");

        Object layouts = Array.newInstance(memoryLayoutClass, argumentLayouts.length);
        for (int i = 0; i < argumentLayouts.length; i++) {
            Array.set(layouts, i, argumentLayouts[i]);
        }
        Object descriptor;
        if (returnLayout == null) {
            descriptor = functionDescriptorClass.getMethod("ofVoid", layouts.getClass()).invoke(null, layouts);
        } else {
            descriptor = functionDescriptorClass.getMethod("of", memoryLayoutClass, layouts.getClass())
                    .invoke(null, returnLayout, layouts);
        }

        Method findOrThrow = opensslH.getDeclaredMethod("findOrThrow", String.class);
        findOrThrow.setAccessible(true);
        Object address = findOrThrow.invoke(null, symbol);

        Object linker = linkerClass.getMethod("nativeLinker").invoke(null);
        Object options = Array.newInstance(linkerOptionClass, 0);
        return (MethodHandle) linkerClass.getMethod("downcallHandle", memorySegmentClass, functionDescriptorClass,
                options.getClass()).invoke(linker, address, descriptor, options);
    }


    /*
     * Describes the OCSP response the test OCSP responder will return.
     */
    private static class ResponseSpec {
        private final int certStatus;
        private final Object signerCert;
        private final Object signerKey;
        private Object statusCert = ocspLeafCert;
        private boolean copyNonce = true;
        private long thisUpdateOffset = -60;
        private Long nextUpdateOffset = Long.valueOf(ONE_DAY);

        ResponseSpec(int certStatus, Object signerCert, Object signerKey) {
            this.certStatus = certStatus;
            this.signerCert = signerCert;
            this.signerKey = signerKey;
        }
    }
}
