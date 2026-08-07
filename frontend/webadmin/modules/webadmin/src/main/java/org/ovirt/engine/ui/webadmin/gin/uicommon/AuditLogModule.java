package org.ovirt.engine.ui.webadmin.gin.uicommon;

import org.ovirt.engine.ui.common.presenter.popup.DefaultConfirmationPopupPresenterWidget;
import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.common.uicommon.model.MainViewModelProvider;
import org.ovirt.engine.ui.uicommonweb.models.AuditLogListModel;

import com.google.gwt.event.shared.EventBus;
import com.google.gwt.inject.client.AbstractGinModule;
import com.google.inject.Provider;
import com.google.inject.Provides;
import com.google.inject.Singleton;

public class AuditLogModule extends AbstractGinModule {

    @Provides
    @Singleton
    public MainModelProvider<Object, AuditLogListModel> getAuditLogListProvider(EventBus eventBus,
            final Provider<DefaultConfirmationPopupPresenterWidget> defaultConfirmPopupProvider,
            final Provider<AuditLogListModel> modelProvider) {
        MainViewModelProvider<Object, AuditLogListModel> mainTabAuditLogModelProvider =
                new MainViewModelProvider<>(eventBus, defaultConfirmPopupProvider);
        mainTabAuditLogModelProvider.setModelProvider(modelProvider);
        return mainTabAuditLogModelProvider;
    }

    @Override
    protected void configure() {
        bind(AuditLogListModel.class).in(Singleton.class);
    }
}
