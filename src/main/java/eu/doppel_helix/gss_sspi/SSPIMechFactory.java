/*
 * Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */
package eu.doppel_helix.gss_sspi;

import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.util.Iterator;
import java.util.Vector;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.ServicePermission;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.GSSUtil;
import static sun.security.jgss.GSSUtil.GSS_KRB5_MECH_OID;
import sun.security.jgss.spi.GSSContextSpi;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;
import sun.security.jgss.spi.MechanismFactory;

public abstract class SSPIMechFactory implements MechanismFactory {

    private static Oid[] nameTypes
            = new Oid[]{GSSName.NT_USER_NAME,
                GSSName.NT_HOSTBASED_SERVICE,
                GSSName.NT_EXPORT_NAME,
                GSSUtil.NT_GSS_KRB5_PRINCIPAL};

    final Oid mechanismOid;
    final protected GSSCaller caller;
    
    public SSPIMechFactory(Oid mechanismOid, GSSCaller caller) {
        this.caller = caller;
        this.mechanismOid = mechanismOid;
    }

    @Override
    public Oid getMechanismOid() {
        return this.mechanismOid;
    }

    @Override
    public Provider getProvider() {
        return SSPIProvider.INSTANCE;
    }

    @Override
    public Oid[] getNameTypes() throws GSSException {
        return nameTypes;
    }

    protected static <K extends SSPICredElement> K getCredFromSubject(GSSNameSpi name,
            boolean initiate, Oid mechanism, Class<K> targetClass)
            throws GSSException {
        Vector<K> creds
                = searchSubject(name, mechanism, initiate, targetClass);

        K result = ((creds == null || creds.isEmpty())
                ? null : creds.firstElement());

        // Force permission check before returning the cred to caller
        if (result != null) {
            if (initiate) {
                checkInitCredPermission((SSPINameElement) result.getName());
            } else {
                checkAcceptCredPermission((SSPINameElement) result.getName(), name);
            }
        }
        return result;
    }
    
    /**
     * Searches the private credentials of current Subject with the
     * specified criteria and returns the matching GSSCredentialSpi
     * object out of Sun's impl of GSSCredential. Returns null if
     * no Subject present or a Vector which contains 0 or more
     * matching GSSCredentialSpi objects.
     */
    protected static <T extends GSSCredentialSpi> Vector<T>
            searchSubject(final GSSNameSpi name,
                          final Oid mech,
                          final boolean initiate,
                          final Class<? extends T> credCls) {
        debug("Search Subject for " + mech +
              (initiate? " INIT" : " ACCEPT") + " cred (" +
              (name == null? "<<DEF>>" : name.toString()) + ", " +
              credCls.getName() + ")");
        final AccessControlContext acc = AccessController.getContext();
        try {
            Vector<T> creds =
                AccessController.doPrivileged
                (new PrivilegedExceptionAction<Vector<T>>() {
                    public Vector<T> run() throws Exception {
                        Subject accSubj = Subject.getSubject(acc);
                        Vector<T> result = null;
                        if (accSubj != null) {
                            result = new Vector<T>();
                            Iterator<? extends T> iterator =
                                accSubj.getPrivateCredentials
                                (credCls).iterator();
                            while (iterator.hasNext()) {
                                T ce = iterator.next();
                                if(name == null ||
                                     name.equals((Object) ce.getName())) {
                                    result.add(credCls.cast(ce));
                                } else {
                                    debug("......Discard element");
                                }
                            }
                        } else debug("No Subject");
                        return result;
                    }
                });
            return creds;
        } catch (PrivilegedActionException pae) {
            debug("Unexpected exception when searching Subject:");
            if (SSPIProvider.DEBUG) pae.printStackTrace();
            return null;
        }
    }

    @Override
    public GSSNameSpi getNameElement(String nameStr, Oid nameType) throws GSSException {
        return SSPINameElement.getInstance(nameStr, nameType);
    }

    @Override
    public GSSNameSpi getNameElement(byte[] name, Oid nameType) throws GSSException {
        return SSPINameElement.getInstance(new String(name), nameType);
    }

    protected static void checkInitCredPermission(SSPINameElement name) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            String realm = (name.getPrincipalName()).getRealmAsString();
            String tgsPrincipal = "krbtgt/" + realm + '@' + realm;
            ServicePermission perm
                    = new ServicePermission(tgsPrincipal, "initiate");
            try {
                sm.checkPermission(perm);
            } catch (SecurityException e) {
                if (SSPIProvider.DEBUG) {
                    System.out.println("Permission to initiate"
                            + "kerberos init credential" + e.getMessage());
                }
                throw e;
            }
        }
    }

    protected static void checkAcceptCredPermission(SSPINameElement name,
            GSSNameSpi originalName) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null && name != null) {
            ServicePermission perm = new ServicePermission(name.getPrincipalName().getName(), "accept");
            try {
                sm.checkPermission(perm);
            } catch (SecurityException e) {
                if (originalName == null) {
                    // Don't disclose the name of the principal
                    e = new SecurityException("No permission to acquire "
                            + "Kerberos accept credential");
                    // Don't call e.initCause() with caught exception
                }
                throw e;
            }
        }
    }
            
    protected static void debug(String message) {
        if (SSPIProvider.DEBUG) {
            assert(message != null);
            System.out.println(message);
        }
    }
}
