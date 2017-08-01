
package eu.doppel_helix.gss_sspi;

import org.ietf.jgss.*;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.GSSUtil;

class NegotiateContext extends SSPIContext {

    public NegotiateContext(GSSCaller caller, SSPINameElement peerName, SSPICredElement myCred, int lifetime) throws GSSException {
        super(caller, peerName, myCred, lifetime);
    }

    public NegotiateContext(GSSCaller caller, SSPICredElement myCred) throws GSSException {
        super(caller, myCred);
    }

    public NegotiateContext(GSSCaller caller, byte[] interProcessToken) throws GSSException {
        super(caller, interProcessToken);
    }
    
    @Override
    protected SSPICredElement createCredential(SSPINameElement name) throws GSSException {
        return NegotiateCredElement.getInstance(getCaller(), name, GSSCredential.DEFAULT_LIFETIME);
    }

    @Override
    public Oid getMech() throws GSSException {
        return SSPIProvider.SPNEGO_MECH_OID;
    }

}
