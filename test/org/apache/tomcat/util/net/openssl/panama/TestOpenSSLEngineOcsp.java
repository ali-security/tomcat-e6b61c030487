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
import java.security.KeyStore;
import java.security.cert.Certificate;

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
 * The test sources are compiled for Java 11 so all access to the FFM API and to
 * the FFM based classes is via reflection.
 */
public class TestOpenSSLEngineOcsp {

    // Constants from OpenSSL's x509_vfy.h and ocsp.h
    private static final int X509_V_ERR_UNABLE_TO_GET_CRL = 3;
    private static final int X509_V_ERR_APPLICATION_VERIFICATION = 50;
    private static final int V_OCSP_CERTSTATUS_UNKNOWN = 2;

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

    private static Object leaf;
    private static Object issuer;

    private static HttpServer ocspResponder;

    private Object sslCtx;
    private Object engineState;
    private Object x509ctx;


    @BeforeClass
    public static void setUp() throws Exception {
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
        classArena = arenaClass.getMethod("ofAuto").invoke(null);

        // Functions not exposed by openssl_h
        x509StoreCtxNew = downcall("X509_STORE_CTX_new", addressLayout);
        x509StoreCtxFree = downcall("X509_STORE_CTX_free", null, addressLayout);
        x509StoreCtxSetExData = downcall("X509_STORE_CTX_set_ex_data", intLayout,
                addressLayout, intLayout, addressLayout);

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

        // OCSP responder that never provides a usable response
        ocspResponder = HttpServer.create(new InetSocketAddress(HOST, 0), 0);
        ocspResponder.createContext("/error", exchange -> respond(exchange, 500, new byte[0]));
        ocspResponder.createContext("/invalid", exchange -> respond(exchange, 200,
                "This is not an OCSP response".getBytes(StandardCharsets.ISO_8859_1)));
        ocspResponder.createContext("/large", exchange -> respond(exchange, 200, new byte[200 * 1024]));
        ocspResponder.start();
    }


    @AfterClass
    public static void tearDown() throws Exception {
        if (ocspResponder != null) {
            ocspResponder.stop(0);
            ocspResponder = null;
        }
        if (leaf != null) {
            call("X509_free", leaf);
            leaf = null;
        }
        if (issuer != null) {
            call("X509_free", issuer);
            issuer = null;
        }
    }


    @After
    public void releaseVerificationContext() throws Throwable {
        if (engineState != null) {
            // Frees the SSL and the BIO
            ((Runnable) engineState).run();
            engineState = null;
        }
        if (sslCtx != null) {
            call("SSL_CTX_free", sslCtx);
            sslCtx = null;
        }
        if (x509ctx != null) {
            x509StoreCtxFree.invokeWithArguments(x509ctx);
            x509ctx = null;
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


    private void doTestOcspFailure(URL url, int expectedError) throws Throwable {
        createVerificationContext(false);

        Assert.assertEquals(V_OCSP_CERTSTATUS_UNKNOWN, processOCSPRequest(url));
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


    private void createVerificationContext(boolean noOcspCheck) throws Throwable {
        x509ctx = x509StoreCtxNew.invokeWithArguments();
        Assert.assertNotEquals(nullSegment, x509ctx);

        sslCtx = call("SSL_CTX_new", call("TLS_server_method"));
        Object ssl = call("SSL_new", sslCtx);
        Object networkBIO = call("BIO_new", call("BIO_s_mem"));

        Class<?> engineStateClass = Class.forName(ENGINE + "$EngineState");
        Constructor<?> constructor = engineStateClass.getDeclaredConstructor(memorySegmentClass,
                memorySegmentClass, int.class, boolean.class);
        constructor.setAccessible(true);
        engineState = constructor.newInstance(ssl, networkBIO, Integer.valueOf(10), Boolean.valueOf(noOcspCheck));

        // Equivalent of client certificate verification "required"
        Field certificateVerifyMode = engineStateClass.getDeclaredField("certificateVerifyMode");
        certificateVerifyMode.setAccessible(true);
        certificateVerifyMode.setInt(engineState, ((Integer) call("SSL_VERIFY_FAIL_IF_NO_PEER_CERT")).intValue());

        // Associate the verification context with the SSL instance
        Object idx = call("SSL_get_ex_data_X509_STORE_CTX_idx");
        Object rc = x509StoreCtxSetExData.invokeWithArguments(x509ctx, idx, ssl);
        Assert.assertEquals(Integer.valueOf(1), rc);
    }


    private int processOCSPRequest(URL url) throws Exception {
        Method processOCSPRequest = Class.forName(ENGINE).getDeclaredMethod("processOCSPRequest", URL.class,
                memorySegmentClass, memorySegmentClass, memorySegmentClass, arenaClass);
        processOCSPRequest.setAccessible(true);
        Object localArena = arenaClass.getMethod("ofConfined").invoke(null);
        try {
            return ((Integer) processOCSPRequest.invoke(null, url, issuer, leaf, x509ctx, localArena)).intValue();
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


    private static Object toNativeX509(Certificate certificate) throws Exception {
        byte[] der = certificate.getEncoded();
        Object derSegment = arenaClass.getMethod("allocateFrom",
                Class.forName("java.lang.foreign.ValueLayout$OfByte"), byte[].class)
                .invoke(classArena, byteLayout, der);
        Object derPointer = arenaClass.getMethod("allocateFrom",
                Class.forName("java.lang.foreign.AddressLayout"), memorySegmentClass)
                .invoke(classArena, addressLayout, derSegment);
        Object x509 = call("d2i_X509", nullSegment, derPointer, Long.valueOf(der.length));
        Assert.assertNotEquals(nullSegment, x509);
        return x509;
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
}
