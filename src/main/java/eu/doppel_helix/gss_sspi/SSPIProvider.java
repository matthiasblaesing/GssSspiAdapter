package eu.doppel_helix.gss_sspi;

import java.security.AccessController;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashSet;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;

public class SSPIProvider extends Provider {
    static final boolean DEBUG;
    
    public static final Oid KRB5_MECH_OID;
    public static final Oid NTML_MECH_OID;
    public static final Oid SPNEGO_MECH_OID;
    
    static final SSPIProvider INSTANCE;
    
    static {
        try {
            KRB5_MECH_OID = new Oid("1.2.840.113554.1.2.2");
            NTML_MECH_OID = new Oid("1.3.6.1.4.1.311.2.2.10");
            SPNEGO_MECH_OID = new Oid("1.3.6.1.5.5.2");
        } catch (GSSException ex) {
            throw new RuntimeException(ex);
        }
        DEBUG = AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            @Override
            public Boolean run() {
                return Boolean.getBoolean("eu.doppel_helix.gss_sspi.debug");
            }
        });
        
        INSTANCE = new SSPIProvider();
    }
    
    public SSPIProvider() {
        // This is a crude Hack - the Oracle JDK and OpenJDK try to be clever
        // in initSecContext and handle the GSS Headers above the SPI level
        // this breaks implementations, where no GSS header is present or where
        // the implementation deals with the headers itself.
        //
        // There is only one special case: A provided names "SunNativeGSS" will
        // recieve and send the raw byte arrays created by the implementation
        super("SunNativeGSS", 0.1, "Integration of Windows SSPI into GGS Handling");

        AccessController.doPrivileged(new PrivilegedAction<Void>() {
            @Override
            public Void run() {
                put("GssApiMechanism." + KRB5_MECH_OID.toString(),
                        "eu.doppel_helix.gss_sspi.Krb5MechFactory");
                put("GssApiMechanism." + NTML_MECH_OID.toString(),
                        "eu.doppel_helix.gss_sspi.NTLMMechFactory");
                put("GssApiMechanism." + SPNEGO_MECH_OID.toString(),
                        "eu.doppel_helix.gss_sspi.NegotiateMechFactory");
                return null;
            }
        });

    }
    
    public static Subject createSubjectForCurrentUser(int usage) throws GSSException {
        Security.insertProviderAt(new SSPIProvider(), 1);

        // It is unclear why it is possible to acquire a credential handle
        // for kerberos, if the windows system is not joined to a domain,
        // thus lacking a REALM....
        Krb5CredElement krb5 = Krb5CredElement.aquireCurrentUser(usage);
        NTLMCredElement ntlm = NTLMCredElement.aquireCurrentUser(usage);
        NegotiateCredElement negotiate = NegotiateCredElement.aquireCurrentUser(usage);
        
        HashSet<SSPICredElement> privateCredentials = new HashSet<>();
        privateCredentials.add(krb5);
        privateCredentials.add(ntlm);
        privateCredentials.add(negotiate);

        HashSet<Principal> principals = new HashSet<>();
        for(SSPICredElement cred: privateCredentials) {
            principals.add(new KerberosPrincipal(cred.getName().toString(), KerberosPrincipal.KRB_NT_PRINCIPAL));
        }
        
        return new Subject(false, 
                principals, 
                Collections.EMPTY_SET, 
                privateCredentials
        );
    }
}
