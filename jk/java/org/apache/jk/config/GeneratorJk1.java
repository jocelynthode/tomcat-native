/*
 * ====================================================================
 *
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 1999 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution, if
 *    any, must include the following acknowlegement:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowlegement may appear in the software itself,
 *    if and wherever such third-party acknowlegements normally appear.
 *
 * 4. The names "The Jakarta Project", "Tomcat", and "Apache Software
 *    Foundation" must not be used to endorse or promote products derived
 *    from this software without prior written permission. For written
 *    permission, please contact apache@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache"
 *    nor may "Apache" appear in their names without prior written
 *    permission of the Apache Group.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 * [Additional notices, if required by prior licensing conditions]
 *
 */
package org.apache.jk.config;

import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;

import org.apache.tomcat.util.IntrospectionUtils;

import javax.xml.parsers.*;

/* Yes, it's using DOM */
import org.w3c.dom.*;
import org.xml.sax.*;


/* Naming conventions:

JK_CONF_DIR == serverRoot/work  ( XXX /jkConfig ? )

- Each vhost has a sub-dir named after the canonycal name

- For each webapp in a vhost, there is a separate WEBAPP_NAME.jkmap

- In httpd.conf ( or equivalent servers ), in each virtual host you
should "Include JK_CONF_DIR/VHOST/jk_apache.conf". The config
file will contain the Alias declarations and other rules required
for apache operation. Same for other servers. 

- WebXml2Jk will be invoked by a config tool or automatically for each
webapp - it'll generate the WEBAPP.jkmap files and config fragments.

WebXml2Jk will _not_ generate anything else but mappings.
It should _not_ try to guess locations or anything else - that's
another components' job.

*/

/**
 *
 * @author Costin Manolache
 */
public class GeneratorJk1 implements WebXml2Jk.MappingGenerator {
    WebXml2Jk wxml;
    String vhost;
    String cpath;
    String worker;
    PrintWriter out;
    
    public void setWebXmlReader(WebXml2Jk wxml ) {
        this.wxml=wxml;
        vhost=wxml.vhost;
        cpath=wxml.cpath;
        worker=wxml.worker;
    }

    public void generateStart( ) throws IOException  {
        File base=wxml.getJkDir();
        File outF=new File(base, "jk.conf");
        out=new PrintWriter( new FileWriter( outF ));
        
        out.println("# This must be included in the virtual host section for " + vhost );
    }

    public void generateEnd() {
        out.close();
    }

    
    public void generateServletMapping( String servlet, String url ) {
        out.println( "JkMount " + cpath + url + " " + worker);
    }

    public void generateFilterMapping( String servlet, String url ) {
        out.println( "JkMount " + cpath + url + " " + worker);
    }

    public void generateLoginConfig( String loginPage,
                                        String errPage, String authM ) {
        out.println( "JkMount " + cpath + loginPage + " " + worker);
    }

    public void generateErrorPage( int err, String location ) {

    }

    public void generateMimeMapping( String ext, String type ) {

    }
    
    public void generateWelcomeFiles( Vector wf ) {

    }
                                            
    
    public void generateConstraints( Vector urls, Vector methods, Vector roles, boolean isSSL ) {
        for( int i=0; i<urls.size(); i++ ) {
            String url=(String)urls.elementAt(i);

            out.println( "JkMount " + cpath + url + " " + worker);
        }
    }
}
