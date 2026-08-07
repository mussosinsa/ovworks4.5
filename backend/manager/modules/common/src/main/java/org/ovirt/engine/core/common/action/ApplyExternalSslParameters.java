package org.ovirt.engine.core.common.action;

public class ApplyExternalSslParameters extends ActionParametersBase {

    private static final long serialVersionUID = 1L;

    private String serverPrivateKeyPath;
    private String serverCertificatePath;
    private String caChainPath;
    private String serverPrivateKeyContent;
    private String serverCertificateContent;
    private String caChainContent;

    public ApplyExternalSslParameters() {
        // For serialization.
    }

    public ApplyExternalSslParameters(String serverPrivateKeyPath, String serverCertificatePath, String caChainPath) {
        this.serverPrivateKeyPath = serverPrivateKeyPath;
        this.serverCertificatePath = serverCertificatePath;
        this.caChainPath = caChainPath;
    }

    public String getServerPrivateKeyPath() {
        return serverPrivateKeyPath;
    }

    public void setServerPrivateKeyPath(String serverPrivateKeyPath) {
        this.serverPrivateKeyPath = serverPrivateKeyPath;
    }

    public String getServerCertificatePath() {
        return serverCertificatePath;
    }

    public void setServerCertificatePath(String serverCertificatePath) {
        this.serverCertificatePath = serverCertificatePath;
    }

    public String getCaChainPath() {
        return caChainPath;
    }

    public void setCaChainPath(String caChainPath) {
        this.caChainPath = caChainPath;
    }

    public String getServerPrivateKeyContent() {
        return serverPrivateKeyContent;
    }

    public void setServerPrivateKeyContent(String serverPrivateKeyContent) {
        this.serverPrivateKeyContent = serverPrivateKeyContent;
    }

    public String getServerCertificateContent() {
        return serverCertificateContent;
    }

    public void setServerCertificateContent(String serverCertificateContent) {
        this.serverCertificateContent = serverCertificateContent;
    }

    public String getCaChainContent() {
        return caChainContent;
    }

    public void setCaChainContent(String caChainContent) {
        this.caChainContent = caChainContent;
    }
}
