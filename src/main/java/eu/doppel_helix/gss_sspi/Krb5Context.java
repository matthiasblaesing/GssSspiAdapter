
package eu.doppel_helix.gss_sspi;

import org.ietf.jgss.*;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.GSSUtil;

class Krb5Context extends SSPIContext {

    public Krb5Context(GSSCaller caller, SSPINameElement peerName, SSPICredElement myCred, int lifetime) throws GSSException {
        super(caller, peerName, myCred, lifetime);
    }

    public Krb5Context(GSSCaller caller, SSPICredElement myCred) throws GSSException {
        super(caller, myCred);
    }

    public Krb5Context(GSSCaller caller, byte[] interProcessToken) throws GSSException {
        super(caller, interProcessToken);
    }
    
    @Override
    protected SSPICredElement createCredential(SSPINameElement name) throws GSSException {
        return Krb5CredElement.getInstance(getCaller(), name, GSSCredential.DEFAULT_LIFETIME);
    }

    @Override
    public Oid getMech() throws GSSException {
        return SSPIProvider.KRB5_MECH_OID;
    }

}
