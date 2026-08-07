package org.ovirt.engine.ui.webadmin.gin.uicommon;

import org.ovirt.engine.ui.common.presenter.popup.DefaultConfirmationPopupPresenterWidget;
import org.ovirt.engine.ui.common.uicommon.model.MainModelProvider;
import org.ovirt.engine.ui.common.uicommon.model.MainViewModelProvider;
import org.ovirt.engine.ui.uicommonweb.models.SecuritySettingsListModel;

import com.google.gwt.event.shared.EventBus;
import com.google.gwt.inject.client.AbstractGinModule;
import com.google.inject.Provider;
import com.google.inject.Provides;
import com.google.inject.Singleton;

public class SecuritySettingsModule extends AbstractGinModule {

    @Provides
    @Singleton
    public MainModelProvider<Object, SecuritySettingsListModel> getSecuritySettingsListProvider(EventBus eventBus,
            final Provider<DefaultConfirmationPopupPresenterWidget> defaultConfirmPopupProvider,
            final Provider<SecuritySettingsListModel> modelProvider) {
        MainViewModelProvider<Object, SecuritySettingsListModel> mainTabSecuritySettingsModelProvider =
                new MainViewModelProvider<>(eventBus, defaultConfirmPopupProvider);
        mainTabSecuritySettingsModelProvider.setModelProvider(modelProvider);
        return mainTabSecuritySettingsModelProvider;
    }

    @Override
    protected void configure() {
        bind(SecuritySettingsListModel.class).in(Singleton.class);
    }
}
