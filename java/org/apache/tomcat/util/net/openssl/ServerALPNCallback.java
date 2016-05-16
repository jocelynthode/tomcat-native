package org.apache.tomcat.util.net.openssl;

/**
 * @author Stuart Douglas
 */
public interface ServerALPNCallback {

    String select(String[] protocols);
}
