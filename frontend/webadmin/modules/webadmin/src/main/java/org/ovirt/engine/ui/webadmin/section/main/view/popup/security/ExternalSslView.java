package org.ovirt.engine.ui.webadmin.section.main.view.popup.security;

import org.gwtbootstrap3.client.ui.Button;
import org.gwtbootstrap3.client.ui.constants.ButtonType;
import org.ovirt.engine.core.common.action.ActionType;
import org.ovirt.engine.core.common.action.ApplyExternalSslParameters;
import org.ovirt.engine.ui.frontend.Frontend;

import com.google.gwt.user.client.Window;
import com.google.gwt.user.client.ui.Composite;
import com.google.gwt.user.client.ui.FileUpload;
import com.google.gwt.user.client.ui.FlowPanel;
import com.google.gwt.user.client.ui.HTML;
import com.google.gwt.user.client.ui.Label;

public class ExternalSslView extends Composite {

    private final Button applyButton = new Button("외부 SSL 적용"); //$NON-NLS-1$
    private final FileUpload privateKeyUpload = new FileUpload();
    private final FileUpload certificateUpload = new FileUpload();
    private final FileUpload caChainUpload = new FileUpload();

    public ExternalSslView() {
        FlowPanel container = new FlowPanel();
        container.getElement().getStyle().setProperty("padding", "20px"); //$NON-NLS-1$ //$NON-NLS-2$
        container.getElement().getStyle().setProperty("backgroundColor", "#ffffff"); //$NON-NLS-1$ //$NON-NLS-2$

        HTML title = new HTML("<h3>외부 SSL 적용</h3>"); //$NON-NLS-1$
        container.add(title);

        HTML guide = new HTML(
                "<div style='margin-bottom:10px;color:#666;'>" //$NON-NLS-1$
                        + "외부 SSL 적용을 실행하면 engine-setup을 통해 SSL 설정을 적용하고 " //$NON-NLS-1$
                        + "httpd/ovirt-engine 서비스 상태와 Apache 인증서를 검증합니다. " //$NON-NLS-1$
                        + "또한 모든 호스트 인증서 재등록(Enroll Certificate)을 순차 실행합니다. " //$NON-NLS-1$
                        + "실행 전 모든 호스트를 유지보수(Maintenance) 상태로 전환해야 합니다." //$NON-NLS-1$
                        + "</div>"); //$NON-NLS-1$
        container.add(guide);

        privateKeyUpload.getElement().setAttribute("accept", ".key,.pem,.txt"); //$NON-NLS-1$ //$NON-NLS-2$
        privateKeyUpload.getElement().getStyle().setProperty("width", "100%"); //$NON-NLS-1$ //$NON-NLS-2$
        certificateUpload.getElement().setAttribute("accept", ".crt,.cer,.pem,.txt"); //$NON-NLS-1$ //$NON-NLS-2$
        certificateUpload.getElement().getStyle().setProperty("width", "100%"); //$NON-NLS-1$ //$NON-NLS-2$
        caChainUpload.getElement().setAttribute("accept", ".crt,.cer,.pem,.txt"); //$NON-NLS-1$ //$NON-NLS-2$
        caChainUpload.getElement().getStyle().setProperty("width", "100%"); //$NON-NLS-1$ //$NON-NLS-2$

        container.add(new Label("1. 서버 개인키 파일 업로드")); //$NON-NLS-1$
        container.add(privateKeyUpload);
        container.add(new Label("2. 서버 인증서 파일 업로드")); //$NON-NLS-1$
        container.add(certificateUpload);
        container.add(new Label("3. CA 체인 파일 업로드")); //$NON-NLS-1$
        container.add(caChainUpload);

        applyButton.setType(ButtonType.PRIMARY);
        applyButton.addClickHandler(event -> applyExternalSsl());
        container.add(applyButton);

        initWidget(container);
    }

    private void applyExternalSsl() {
        if (!hasSelectedFile(privateKeyUpload) || !hasSelectedFile(certificateUpload) || !hasSelectedFile(caChainUpload)) {
            Window.alert("서버 개인키, 서버 인증서, CA 체인 파일을 모두 업로드해 주세요."); //$NON-NLS-1$
            return;
        }

        applyButton.setEnabled(false);
        readUploadedFile(privateKeyUpload, new FileReadCallback() {
            @Override
            public void onSuccess(String privateKeyFileName, String privateKeyContent) {
                readUploadedFile(certificateUpload, new FileReadCallback() {
                    @Override
                    public void onSuccess(String certFileName, String certContent) {
                        readUploadedFile(caChainUpload, new FileReadCallback() {
                            @Override
                            public void onSuccess(String caFileName, String caContent) {
                                ApplyExternalSslParameters parameters = new ApplyExternalSslParameters();
                                parameters.setServerPrivateKeyContent(privateKeyContent);
                                parameters.setServerCertificateContent(certContent);
                                parameters.setCaChainContent(caContent);

                                Frontend.getInstance().runAction(
                                        ActionType.ApplyExternalSsl,
                                        parameters,
                                        result -> {
                                            applyButton.setEnabled(true);
                                            if (result != null
                                                    && result.getReturnValue() != null
                                                    && result.getReturnValue().getSucceeded()) {
                                                Window.alert("외부 SSL 적용이 완료되었습니다."); //$NON-NLS-1$
                                            } else {
                                                String errorMessage = "외부 SSL 적용에 실패했습니다."; //$NON-NLS-1$
                                                if (result != null
                                                        && result.getReturnValue() != null
                                                        && result.getReturnValue().getExecuteFailedMessages() != null
                                                        && !result.getReturnValue().getExecuteFailedMessages().isEmpty()) {
                                                    errorMessage += "\n" //$NON-NLS-1$
                                                            + String.join("\n", result.getReturnValue().getExecuteFailedMessages()); //$NON-NLS-1$
                                                }
                                                Window.alert(errorMessage);
                                            }
                                        });
                            }

                            @Override
                            public void onError(String errorMessage) {
                                applyButton.setEnabled(true);
                                Window.alert(errorMessage);
                            }
                        });
                    }

                    @Override
                    public void onError(String errorMessage) {
                        applyButton.setEnabled(true);
                        Window.alert(errorMessage);
                    }
                });
            }

            @Override
            public void onError(String errorMessage) {
                applyButton.setEnabled(true);
                Window.alert(errorMessage);
            }
        });
    }

    private native boolean hasSelectedFile(FileUpload upload) /*-{
        var input = upload.@com.google.gwt.user.client.ui.FileUpload::getElement()();
        return !!(input && input.files && input.files.length > 0);
    }-*/;

    private interface FileReadCallback {
        void onSuccess(String fileName, String content);
        void onError(String errorMessage);
    }

    private native void readUploadedFile(FileUpload upload, FileReadCallback callback) /*-{
        var input = upload.@com.google.gwt.user.client.ui.FileUpload::getElement()();
        if (!input || !input.files || input.files.length === 0) {
            callback.@org.ovirt.engine.ui.webadmin.section.main.view.popup.security.ExternalSslView.FileReadCallback::onError(Ljava/lang/String;)(
                "업로드할 파일을 선택해 주세요."
            );
            return;
        }

        var file = input.files[0];
        var reader = new FileReader();
        reader.onload = $entry(function (event) {
            callback.@org.ovirt.engine.ui.webadmin.section.main.view.popup.security.ExternalSslView.FileReadCallback::onSuccess(Ljava/lang/String;Ljava/lang/String;)(
                file.name,
                event.target.result
            );
        });
        reader.onerror = $entry(function () {
            callback.@org.ovirt.engine.ui.webadmin.section.main.view.popup.security.ExternalSslView.FileReadCallback::onError(Ljava/lang/String;)(
                "파일을 읽는 중 오류가 발생했습니다: " + file.name
            );
        });
        reader.readAsText(file);
    }-*/;
}
