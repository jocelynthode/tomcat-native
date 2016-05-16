package org.apache.tomcat.util.net;

/**
 * Optional interface that can be implemented by
 * {@link javax.net.ssl.SSLEngine}s to indicate that they support ALPN and
 * can provided the protocol agreed with the client.
 */
public interface ProtocolInfo {
    /**
     * ALPN information.
     * @return the protocol selected using ALPN
     */
    public String getNegotiatedProtocol();
}
