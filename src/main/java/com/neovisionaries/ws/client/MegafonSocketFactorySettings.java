package com.neovisionaries.ws.client;

import org.apache.http.conn.scheme.SocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;

import javax.net.ssl.SSLContext;

/**
 * @author Aleksander Melnichnikov
 */
public class MegafonSocketFactorySettings {
    private SocketFactory mSocketFactory;
    private SSLSocketFactory mSSLSocketFactory;
    private SSLContext mSSLContext;


    public SocketFactory getSocketFactory() {
        return mSocketFactory;
    }


    public void setSocketFactory(SocketFactory factory) {
        mSocketFactory = factory;
    }


    public SSLSocketFactory getSSLSocketFactory() {
        return mSSLSocketFactory;
    }


    public void setSSLSocketFactory(SSLSocketFactory factory) {
        mSSLSocketFactory = factory;
    }


    public SSLContext getSSLContext() {
        return mSSLContext;
    }


    public void setSSLContext(SSLContext context) {
        mSSLContext = context;
    }


    public SocketFactory selectSocketFactory(boolean secure) {
        return SSLSocketFactory.getSocketFactory();
    }
}
