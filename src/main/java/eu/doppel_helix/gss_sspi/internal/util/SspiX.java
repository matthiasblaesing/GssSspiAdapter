package eu.doppel_helix.gss_sspi.internal.util;



import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import static com.sun.jna.Structure.createFieldsOrder;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.win32.W32APITypeMapper;
import java.util.Date;
import java.util.List;

public interface SspiX extends Sspi {

    public static final int SECPKG_CRED_ATTR_NAMES = 1;
    
    public static final int SECPKG_ATTR_SESSION_KEY = 9;
    public static final int SECPKG_ATTR_KEY_INFO = 5;
    public static final int SECPKG_ATTR_LIFESPAN = 2;
    public static final int SECPKG_ATTR_SIZES = 0;
    
    public static final int SECPKG_ATTR_NEGOTIATION_INFO = 12;
    public static final int SECPKG_ATTR_FLAGS = 14;
    public static final int SECPKG_ATTR_STREAM_SIZES = 4;

    public static final int ISC_REQ_DATAGRAM = 0x00000400;

    /**
     * Negotiation has been completed.
     */
    int SECPKG_NEGOTIATION_COMPLETE = 0;
    /**
     * Negotiations not yet completed.
     */
    int SECPKG_NEGOTIATION_OPTIMISTIC = 1;
    /**
     * Negotiations in progress.
     */
    int SECPKG_NEGOTIATION_IN_PROGRESS = 2;
    int SECPKG_NEGOTIATION_DIRECT = 3;
    int SECPKG_NEGOTIATION_TRY_MULTICRED = 4;

    /**
     * Undefined, replaced by provider
     */
    int SECBUFFER_EMPTY = 0;
    /**
     * Packet data
     */
    int SECBUFFER_DATA = 1;
    /**
     * Security token
     */
    int SECBUFFER_TOKEN = 2;
    /**
     * Package specific parameters
     */
    int SECBUFFER_PKG_PARAMS = 3;
    /**
     * Missing Data indicator
     */
    int SECBUFFER_MISSING = 4;
    /**
     * Extra data
     */
    int SECBUFFER_EXTRA = 5;
    /**
     * Security Trailer
     */
    int SECBUFFER_STREAM_TRAILER = 6;
    /**
     * Security Header
     */
    int SECBUFFER_STREAM_HEADER = 7;
    /**
     * Hints from the negotiation pkg
     */
    int SECBUFFER_NEGOTIATION_INFO = 8;
    /**
     * non-data padding
     */
    int SECBUFFER_PADDING = 9;
    /**
     * whole encrypted message
     */
    int SECBUFFER_STREAM = 10;
    /**
     *     */
    int SECBUFFER_MECHLIST = 11;
    /**
     *     */
    int SECBUFFER_MECHLIST_SIGNATURE = 12;
    /**
     * obsolete
     */
    int SECBUFFER_TARGET = 13;
    /**
     *     */
    int SECBUFFER_CHANNEL_BINDINGS = 14;
    /**
     *     */
    int SECBUFFER_CHANGE_PASS_RESPONSE = 15;
    /**
     *     */
    int SECBUFFER_TARGET_HOST = 16;
    /**
     *     */
    int SECBUFFER_ALERT = 17;
    /**
     *     */
    int SECBUFFER_ATTRMASK = 0xF0000000;
    /**
     * Buffer is read-only, no checksum
     */
    int SECBUFFER_READONLY = 0x80000000;
    /**
     * Buffer is read-only, and checksummed
     */
    int SECBUFFER_READONLY_WITH_CHECKSUM = 0x10000000;
    /**
     * Flags reserved to security system
     */
    int SECBUFFER_RESERVED = 0x60000000;
    
    /**
     * Produce a header or trailer but do not encrypt the message.
     */
    public static final int SECQOP_WRAP_NO_ENCRYPT = 0x80000001;

    public static class SecPkgCredentials_Names extends Structure {

        public static class ByReference extends SecPkgCredentials_Names implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("sUserName");

        /**
         * The first entry in an array of SecPkgInfo structures.
         */
        public Pointer sUserName;

        public SecPkgCredentials_Names() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }

        public synchronized String getUserName() {
            if(sUserName == null) {
                return null;
            }
            return Boolean.getBoolean("w32.ascii") ? sUserName.getString(0) : sUserName.getWideString(0);
        }
        
        public synchronized void free() {
            if(sUserName != null) {
                Secur32X.INSTANCE.FreeContextBuffer(sUserName);
                sUserName = null;
            }
        }
    }
    
    public static class SecPkgContext_SessionKey extends Structure {

        public static class ByReference extends SecPkgContext_SessionKey implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("SessionKeyLength", "SessionKey");

        /**
         * Size, in bytes, of the session key.
         */
        public int SessionKeyLength;
        
        /**
         * The session key for the security context.
         */
        public Pointer SessionKey;

        public SecPkgContext_SessionKey() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }

        public byte[] getSessionKey() {
            if(SessionKey == null) {
                return null;
            }
            return SessionKey.getByteArray(0, SessionKeyLength);
        }
        
        public synchronized void free() {
            if(SessionKey != null) {
                Secur32X.INSTANCE.FreeContextBuffer(SessionKey);
                SessionKey = null;
            }
        }
    }
    
    public static class SecPkgContext_KeyInfo extends Structure {

        public static class ByReference extends SecPkgContext_KeyInfo implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("sSignatureAlgorithmName", "sEncryptAlgorithmName","KeySize", "SignatureAlgorithm", "EncryptAlgorithm");

        /**
         * Name, if available, of the algorithm used for generating signatures, for example "MD5" or "SHA-2".
         */
        public Pointer sSignatureAlgorithmName;
        
        /**
         * Name, if available, of the algorithm used for encrypting messages. Reserved for future use.
         */
        public Pointer sEncryptAlgorithmName;
        
        /**
         * Specifies the effective key length, in bits, for the session key. This is typically 40, 56, or 128 bits.
         */
        public int KeySize;
        
        /**
         * Specifies the algorithm identifier (ALG_ID) used for generating signatures, if available.
         */
        public int SignatureAlgorithm;
        
        /**
         * Specifies the algorithm identifier (ALG_ID) used for encrypting messages. Reserved for future use.
         */
        public int EncryptAlgorithm;

        public SecPkgContext_KeyInfo() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }

        public synchronized String getSignatureAlgorithmName() {
            if(sSignatureAlgorithmName == null) {
                return null;
            }
            return Boolean.getBoolean("w32.ascii") ? sSignatureAlgorithmName.getString(0) : sSignatureAlgorithmName.getWideString(0);
        }
        
        public synchronized String getEncryptAlgorithmName() {
            if(sEncryptAlgorithmName == null) {
                return null;
            }
            return Boolean.getBoolean("w32.ascii") ? sEncryptAlgorithmName.getString(0) : sEncryptAlgorithmName.getWideString(0);
        }
        
        public synchronized void free() {
            if(sSignatureAlgorithmName != null) {
                Secur32X.INSTANCE.FreeContextBuffer(sSignatureAlgorithmName);
                sSignatureAlgorithmName = null;
            }
            if(sEncryptAlgorithmName != null) {
                Secur32X.INSTANCE.FreeContextBuffer(sEncryptAlgorithmName);
                sEncryptAlgorithmName = null;
            }
        }
    }
    
    public static class SecPkgContext_Lifespan extends Structure {

        public static class ByReference extends SecPkgContext_Lifespan implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("tsStart", "tsExpiry");

        /**
         * Time at which the context was established.
         */
        public TimeStamp tsStart;
        
        /**
         * Time at which the context will expire.
         */
        public TimeStamp tsExpiry;

        public SecPkgContext_Lifespan() {
            super(W32APITypeMapper.DEFAULT);
        }

        public Date getStartAsDate()  {
            if(tsStart != null && (tsStart.dwLower != 0 || tsStart.dwUpper != 0)) {
                return WinBase.FILETIME.filetimeToDate(tsStart.dwUpper, tsStart.dwLower);
            }
            return null;
        }
        
        public Date getExpiryAsDate()  {
            if(tsExpiry != null && (tsExpiry.dwLower != 0 || tsExpiry.dwUpper != 0)) {
                return WinBase.FILETIME.filetimeToDate(tsExpiry.dwUpper, tsExpiry.dwLower);
            }
            return null;
        }
        
        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
    }
    
    public static class SecPkgContext_Sizes extends Structure {

        public static class ByReference extends SecPkgContext_Sizes implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("cbMaxToken", "cbMaxSignature", "cbBlockSize", "cbSecurityTrailer");

        /**
         * Specifies the maximum size of the security token used in the authentication exchanges.
         */
        public int cbMaxToken;
        
        /**
         * Specifies the maximum size of the signature created by the MakeSignature function. This member must be zero if integrity services are not requested or available.
         */
        public int cbMaxSignature;
        
        /**
         * Specifies the preferred integral size of the messages. For example, eight indicates that messages should be of size zero mod eight for optimal performance. Messages other than this block size can be padded.
         */
        public int cbBlockSize;
        
        /**
         * Size of the security trailer to be appended to messages. This member should be zero if the relevant services are not requested or available.
         */
        public int cbSecurityTrailer;

        public SecPkgContext_Sizes() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }

        @Override
        public String toString() {
            return "SecPkgContext_Sizes{" + "cbMaxToken=" + cbMaxToken +
                    ", cbMaxSignature=" + cbMaxSignature + ", cbBlockSize=" +
                    cbBlockSize + ", cbSecurityTrailer=" + cbSecurityTrailer +
                    '}';
        }
    }
    
    public static class SecPkgContext_NegotiationInfo extends Structure {

        public static class ByReference extends SecPkgContext_NegotiationInfo implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("PackageInfo", "NegotiationState");

        /**
         * Time at which the context was established.
         */
        public PSecPkgInfo PackageInfo;

        /**
         * Time at which the context will expire.
         */
        public int NegotiationState;

        public SecPkgContext_NegotiationInfo() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
    }
    
    public static class SecPkgContext_Flags extends Structure {

        public static class ByReference extends SecPkgContext_Flags implements Structure.ByReference {

        }

        public static final List<String> FIELDS = createFieldsOrder("Flags");

        /**
         * Flag values for the current security context. These values correspond
         * to the flags negotiated by the InitializeSecurityContext (General)
         * and AcceptSecurityContext (General) functions.
         */
        public int Flags;

        public SecPkgContext_Flags() {
            super(W32APITypeMapper.DEFAULT);
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
    }
    
    public static class ManagedSecBufferDesc extends SecBufferDesc2 {
                
        private final SecBuffer[] secBuffers;
        
        /**
         * Create a new SecBufferDesc with initial data.
         * @param type Token type.
         * @param token Initial token data.
         */
        public ManagedSecBufferDesc(int type, byte[] token) {
            secBuffers = new SecBuffer[] { new SecBuffer(type, token) };
            pBuffers = secBuffers[0].getPointer();
            cBuffers = secBuffers.length;
        }

        /**
         * Create a new SecBufferDesc with one SecBuffer of a given type and size.
         * @param type type
         * @param tokenSize token size
         */
        public ManagedSecBufferDesc(int type, int tokenSize) {
            secBuffers = new SecBuffer[] { new SecBuffer(type, tokenSize) };
            pBuffers = secBuffers[0].getPointer();
            cBuffers = secBuffers.length;
        }
        
        public ManagedSecBufferDesc(int bufferCount) {
            cBuffers = bufferCount;
            secBuffers = (SecBuffer[]) new SecBuffer().toArray(bufferCount);
            pBuffers = secBuffers[0].getPointer();
            cBuffers = secBuffers.length;
        }

        public SecBuffer getBuffer(int idx) {
            return secBuffers[idx];
        }

        @Override
        public void write() {
            for(SecBuffer sb: secBuffers)  {
                sb.write();
            }
            writeField("ulVersion");
            writeField("pBuffers");
            writeField("cBuffers");
        }

        @Override
        public void read() {
            for (SecBuffer sb : secBuffers) {
                sb.read();
            }
        }

    }
    
    public static class SecBufferDesc2 extends Structure {
        public static final List<String> FIELDS = createFieldsOrder("ulVersion", "cBuffers", "pBuffers");

        /**
         * Version number.
         */
        public int ulVersion = SECBUFFER_VERSION;
        /**
         * Number of buffers.
         */
        public int cBuffers = 1;
        /**
         * Pointer to array of buffers.
         */
        public Pointer pBuffers;

        /**
         * Create a new SecBufferDesc with one SECBUFFER_EMPTY buffer.
         */
        public SecBufferDesc2() {
            super();
        }

        @Override
        protected List<String> getFieldOrder() {
            return FIELDS;
        }
    }
}
