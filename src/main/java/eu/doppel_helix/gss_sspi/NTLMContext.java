
package eu.doppel_helix.gss_sspi;

import org.ietf.jgss.*;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.GSSUtil;

class NTLMContext extends SSPIContext {

    public NTLMContext(GSSCaller caller, SSPINameElement peerName, SSPICredElement myCred, int lifetime) throws GSSException {
        super(caller, peerName, myCred, lifetime);
    }

    public NTLMContext(GSSCaller caller, SSPICredElement myCred) throws GSSException {
        super(caller, myCred);
    }

    public NTLMContext(GSSCaller caller, byte[] interProcessToken) throws GSSException {
        super(caller, interProcessToken);
    }
    
    @Override
    protected SSPICredElement createCredential(SSPINameElement name) throws GSSException {
        return NTLMCredElement.getInstance(getCaller(), name, GSSCredential.DEFAULT_LIFETIME);
    }

    @Override
    public Oid getMech() throws GSSException {
        return SSPIProvider.NTML_MECH_OID;
    }

}
