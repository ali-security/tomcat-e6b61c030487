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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import org.apache.catalina.Context;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.StoreType;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.apache.tomcat.util.net.jsse.PEMFile;
import org.apache.tomcat.util.net.openssl.OpenSSLConf;
import org.apache.tomcat.util.net.openssl.OpenSSLConfCmd;

/**
 * Tests that a CRL configured on a connector is applied consistently by every TLS implementation, regardless of
 * whether the server certificate is provided via a key store or via PEM files.
 * <p>
 * The OpenSSL based implementations used to configure the CRL only when the server certificate and key were supplied
 * as PEM files, so with a key store the CRL was silently dropped and every revoked client certificate was accepted.
 * The FFM implementation additionally only logged - rather than reported - a CRL that could not be loaded.
 * <p>
 * The certificates and CRL used here are issued by a dedicated test CA, see keystore-info.txt.
 */
@RunWith(Parameterized.class)
public class TestCrlSupport extends TomcatBaseTest {

    private static final String CRL_CA_CERT_PEM = TesterSupport.SSL_DIR + "crl-ca-cert.pem";
    private static final String CRL_PEM = TesterSupport.SSL_DIR + "crl-ca-crl.pem";
    private static final String CLIENT_VALID_PEM = TesterSupport.SSL_DIR + "user-crl-valid.pem";
    private static final String CLIENT_REVOKED_PEM = TesterSupport.SSL_DIR + "user-crl-revoked.pem";

    private static final String JSSE_IMPLEMENTATION = "org.apache.tomcat.util.net.jsse.JSSEImplementation";
    private static final String OPENSSL_IMPLEMENTATION = "org.apache.tomcat.util.net.openssl.OpenSSLImplementation";
    private static final String OPENSSL_FFM_IMPLEMENTATION =
            "org.apache.tomcat.util.net.openssl.panama.OpenSSLImplementation";

    /*
     * A well formed PEM block that does not contain a valid CRL. Every TLS implementation has to reject it.
     */
    private static final String INVALID_CRL =
            "-----BEGIN X509 CRL-----\n" + "bm90LWEtdmFsaWQtQ1JM\n" + "-----END X509 CRL-----\n";

    @Parameters(name = "{0} with OpenSSL trust {2}, server certificate from {4}")
    public static Collection<Object[]> parameters() {
        List<Object[]> parameterSets = new ArrayList<>();
        for (StoreType storeType : StoreType.values()) {
            parameterSets.add(new Object[] { "JSSE", Boolean.FALSE, Boolean.FALSE, JSSE_IMPLEMENTATION, storeType });
            parameterSets.add(new Object[] { "OpenSSL", Boolean.TRUE, Boolean.TRUE, OPENSSL_IMPLEMENTATION, storeType });
            parameterSets.add(new Object[] { "OpenSSL", Boolean.TRUE, Boolean.FALSE, OPENSSL_IMPLEMENTATION, storeType });
            parameterSets.add(
                    new Object[] { "OpenSSL-FFM", Boolean.TRUE, Boolean.TRUE, OPENSSL_FFM_IMPLEMENTATION, storeType });
            parameterSets.add(
                    new Object[] { "OpenSSL-FFM", Boolean.TRUE, Boolean.FALSE, OPENSSL_FFM_IMPLEMENTATION, storeType });
        }
        return parameterSets;
    }

    @Parameter(0)
    public String connectorName;

    @Parameter(1)
    public boolean useOpenSSL;

    @Parameter(2)
    public boolean useOpenSSLTrust;

    @Parameter(3)
    public String sslImplementationName;

    @Parameter(4)
    public StoreType serverCertificateStoreType;


    @Override
    public void setUp() throws Exception {
        super.setUp();

        Tomcat tomcat = getTomcatInstance();

        Connector connector = tomcat.getConnector();
        connector.setSecure(true);
        Assert.assertTrue(connector.setProperty("SSLEnabled", "true"));

        SSLHostConfig sslHostConfig = new SSLHostConfig();
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, Type.UNDEFINED);
        sslHostConfig.addCertificate(certificate);
        connector.addSslHostConfig(sslHostConfig);

        sslHostConfig.setSslProtocol("tls");
        // Use TLSv1.2 so a rejected client certificate always fails the handshake
        sslHostConfig.setProtocols(Constants.SSL_PROTO_TLSv1_2);
        sslHostConfig.setCertificateVerification("required");

        // Server certificate (issued by the standard test CA)
        if (serverCertificateStoreType == StoreType.KEYSTORE) {
            certificate.setCertificateKeystoreFile(new File(TesterSupport.LOCALHOST_RSA_JKS).getAbsolutePath());
        } else {
            certificate.setCertificateFile(new File(TesterSupport.LOCALHOST_RSA_CERT_PEM).getAbsolutePath());
            certificate.setCertificateKeyFile(new File(TesterSupport.LOCALHOST_RSA_KEY_PEM).getAbsolutePath());
        }

        // Client certificate trust (the CRL test CA)
        if (useOpenSSLTrust) {
            sslHostConfig.setCaCertificateFile(new File(CRL_CA_CERT_PEM).getAbsolutePath());
            // The test certificates do not specify an OCSP responder so disable OCSP. Revocation is checked via the CRL.
            OpenSSLConf openSslConf = new OpenSSLConf();
            OpenSSLConfCmd noOcspCheck = new OpenSSLConfCmd();
            noOcspCheck.setName("NO_OCSP_CHECK");
            noOcspCheck.setValue("true");
            openSslConf.addCmd(noOcspCheck);
            sslHostConfig.setOpenSslConf(openSslConf);
        } else {
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            trustStore.setCertificateEntry("ca", loadPem(CRL_CA_CERT_PEM).getCertificates().get(0));
            sslHostConfig.setTrustStore(trustStore);
        }

        // The CRL revokes the user-crl-revoked certificate
        sslHostConfig.setCertificateRevocationListFile(new File(CRL_PEM).getAbsolutePath());

        // No file system docBase required
        Context ctx = tomcat.addContext("", null);
        Tomcat.addServlet(ctx, "simple", new TesterSupport.SimpleServlet());
        ctx.addServletMappingDecoded("/", "simple");

        TesterSupport.configureSSLImplementation(tomcat, sslImplementationName, useOpenSSL);
    }


    /*
     * Control for testRevokedClientCertificateIsRejected(). A client certificate that is not revoked must be
     * accepted.
     */
    @Test
    public void testValidClientCertificateIsAccepted() throws Exception {
        configureClient(CLIENT_VALID_PEM);

        startAndCheckConnector();

        ByteChunk res = getUrl("https://localhost:" + getPort() + "/");
        Assert.assertEquals("OK", res.toString());
    }


    /*
     * A client certificate listed in the configured CRL must be rejected. With a server certificate from a key store,
     * the OpenSSL based implementations used to skip the CRL configuration entirely and accepted the revoked
     * certificate.
     */
    @Test
    public void testRevokedClientCertificateIsRejected() throws Exception {
        configureClient(CLIENT_REVOKED_PEM);

        startAndCheckConnector();

        ByteChunk res = null;
        try {
            res = getUrl("https://localhost:" + getPort() + "/");
        } catch (IOException expected) {
            // Expected. The TLS handshake failed as the client certificate has been revoked.
        }
        Assert.assertNull("Revoked client certificate was accepted", res);
    }


    /*
     * A CRL that cannot be loaded must not be silently ignored. If it is, the connector runs without the configured
     * revocation checking. The failure has to prevent the TLS configuration from being used.
     *
     * With a server certificate from a key store this also covers the case where the OpenSSL based implementations
     * skipped the CRL configuration entirely: the CRL file was never read, nothing failed and the connector served
     * requests. testValidClientCertificateIsAccepted() is the control for this test.
     */
    @Test
    public void testInvalidCrlIsNotIgnored() throws Exception {
        /*
         * Seal: Skipped for the Tomcat Native (tcnative) implementation. When the SSL context fails to initialise
         * because the CRL cannot be loaded, the subsequent native clean-up intermittently crashes the test JVM
         * (SIGSEGV in Java_org_apache_tomcat_jni_SSLContext_free, tcnative 2.0.15). This also happens with PEM server
         * certificates, where CRL loading is unchanged by this fix. The revocation fix for tcnative is still covered
         * by testRevokedClientCertificateIsRejected().
         */
        Assume.assumeFalse("tcnative SSLContext clean-up after a failed initialisation can crash the test JVM",
                OPENSSL_IMPLEMENTATION.equals(sslImplementationName));
        File invalidCrl = File.createTempFile("invalid-crl-", ".pem", getTemporaryDirectory());
        addDeleteOnTearDown(invalidCrl);
        Files.write(invalidCrl.toPath(), INVALID_CRL.getBytes(StandardCharsets.US_ASCII));

        Tomcat tomcat = getTomcatInstance();
        SSLHostConfig sslHostConfig = tomcat.getConnector().findSslHostConfigs()[0];
        sslHostConfig.setCertificateRevocationListFile(invalidCrl.getAbsolutePath());
        configureClient(CLIENT_VALID_PEM);

        // Report a connector failure via the connector state rather than via an exception from start()
        tomcat.getConnector().setThrowOnFailure(false);
        tomcat.start();
        if (tomcat.getConnector().getState() != LifecycleState.STARTED) {
            // Expected. The CRL could not be loaded and the connector failed to start.
            return;
        }

        // The connector started. That is only acceptable if the TLS configuration cannot be used.
        Assert.assertTrue("Connector started with a CRL that could not be loaded", useOpenSSL);
        // For the OpenSSL based implementations the SSL context must not have been initialised
        Assert.assertEquals("OpenSSL context initialised with a CRL that could not be loaded", 0,
                sslHostConfig.getOpenSslContext().longValue());

        if (OPENSSL_FFM_IMPLEMENTATION.equals(sslImplementationName)) {
            // and no TLS connection may be accepted using it
            ByteChunk res = null;
            try {
                res = getUrl("https://localhost:" + getPort() + "/");
            } catch (IOException expected) {
                // Expected. The TLS configuration is unusable.
            }
            Assert.assertNull("Connection accepted with a CRL that could not be loaded", res);
        }
    }


    private void startAndCheckConnector() throws Exception {
        Tomcat tomcat = getTomcatInstance();
        tomcat.start();
        Assert.assertEquals(LifecycleState.STARTED, tomcat.getConnector().getState());
        if (useOpenSSL) {
            // Ensure the OpenSSL context was successfully initialised
            Assert.assertNotEquals(0, tomcat.getConnector().findSslHostConfigs()[0].getOpenSslContext().longValue());
        }
    }


    private static void configureClient(String clientPem) throws Exception {
        PEMFile pemFile = loadPem(clientPem);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("client", pemFile.getPrivateKey(), TesterSupport.JKS_PASS.toCharArray(),
                pemFile.getCertificates().toArray(new Certificate[0]));
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, TesterSupport.JKS_PASS.toCharArray());

        SSLContext sc = SSLContext.getInstance(Constants.SSL_PROTO_TLSv1_2);
        sc.init(kmf.getKeyManagers(), TesterSupport.getTrustManagers(), null);
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }


    private static PEMFile loadPem(String path) throws Exception {
        try (InputStream is = new FileInputStream(path)) {
            return new PEMFile(path, is, null, null);
        }
    }
}
