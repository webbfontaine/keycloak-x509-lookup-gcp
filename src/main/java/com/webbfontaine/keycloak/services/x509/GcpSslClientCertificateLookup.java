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

package com.webbfontaine.keycloak.services.x509;

import org.jboss.logging.Logger;
import org.keycloak.common.util.DerUtils;
import org.keycloak.http.HttpRequest;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static java.util.Objects.requireNonNull;
import static java.util.Optional.empty;
import static java.util.Optional.ofNullable;
import static org.keycloak.common.util.Base64.decode;

/**
 * The provider allows to extract X.509 client certificate forwarded
 * to the keycloak middleware configured behind the GCP load balancer.
 */
public class GcpSslClientCertificateLookup implements X509ClientCertificateLookup {

    private static final Logger logger = Logger.getLogger(GcpSslClientCertificateLookup.class);

    private final String sslClientCertHttpHeader;

    private final String sslCertChainHttpHeader;

    public GcpSslClientCertificateLookup(String sslClientCertHttpHeader, String sslCertChainHttpHeader) {
        this.sslClientCertHttpHeader = sslClientCertHttpHeader;
        this.sslCertChainHttpHeader = sslCertChainHttpHeader;
    }


    @Override
    public X509Certificate[] getCertificateChain(HttpRequest httpRequest) throws GeneralSecurityException {
        return getCertificateFromHttpHeader(httpRequest, sslClientCertHttpHeader)
                .stream()
                .flatMap(leaf -> {
                    var trusted = getCertificateChainFromHttpHeader(httpRequest, sslCertChainHttpHeader);
                    return Stream.concat(Stream.of(leaf), trusted.stream());
                }).toArray(X509Certificate[]::new);
    }

    private static Optional<X509Certificate> getCertificateFromHttpHeader(HttpRequest request, String httpHeader) throws GeneralSecurityException {
        try {
            return getHeaderValue(request, httpHeader)
                    .map(GcpSslClientCertificateLookup::decodeCertificateFromDer)
                    .or(() -> {
                        logger.warnf("HTTP header \"%s\" does not contain a valid x.509 certificate", httpHeader);
                        return empty();
                    });
        } catch (Exception e) {
            throw new GeneralSecurityException(e);
        }
    }

    private static List<X509Certificate> getCertificateChainFromHttpHeader(HttpRequest request, String httpHeader) {
        return getHeaderValue(request, httpHeader)
                .map(value -> value.split(","))
                .map(parts -> Stream.of(parts)
                        .map(String::trim)
                        .map(GcpSslClientCertificateLookup::decodeCertificateFromDer)
                        .toList()
                ).orElseGet(() -> {
                    logger.warnf("HTTP header \"%s\" is empty", httpHeader);
                    return Collections.emptyList();
                });
    }

    private static Optional<String> getHeaderValue(HttpRequest httpRequest, String headerName) {
        return ofNullable(httpRequest.getHttpHeaders().getRequestHeaders().getFirst(headerName));
    }

    private static X509Certificate decodeCertificateFromDer(String der) {
        try (var in = binary(requireNonNull(der))) {
            return DerUtils.decodeCertificate(in);
        } catch (Exception e) {
            throw new CertificateDecodingException(e);
        }
    }

    private static InputStream binary(String der) throws GeneralSecurityException {
        try {
            return new ByteArrayInputStream(decode(stripColons(der)));
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    private static String stripColons(String der) {
        // Use simple matching instead of regex
        if (der.startsWith(":") && der.endsWith(":")) {
            return der.substring(1, der.length() - 1);
        }
        return der;
    }

    @Override
    public void close() {
    }
}
