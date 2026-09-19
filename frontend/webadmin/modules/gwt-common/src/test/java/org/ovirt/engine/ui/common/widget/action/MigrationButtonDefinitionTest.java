package org.ovirt.engine.ui.common.widget.action;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.ovirt.engine.core.common.businessentities.VDS;
import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.ui.frontend.AsyncQuery;
import org.ovirt.engine.ui.uicommonweb.dataprovider.AsyncDataProvider;
import org.ovirt.engine.ui.uicompat.IEventListener;
import org.ovirt.engine.ui.uicompat.PropertyChangedEventArgs;

import com.google.gwt.dom.client.Style.HasCssName;
import com.google.gwt.event.logical.shared.InitializeHandler;
import com.google.gwt.event.shared.GwtEvent;
import com.google.gwt.event.shared.HandlerRegistration;
import com.google.gwt.safehtml.shared.SafeHtml;

public class MigrationButtonDefinitionTest {

    /** Stands in for the button ovirt-engine-ui-extensions builds, without GWT underneath it. */
    private static class PluginButton implements ActionButtonDefinition<Void, Object> {

        private final String id;

        private final String text;

        private boolean enabled = true;

        private boolean clicked;

        PluginButton(String id, String text) {
            this.id = id;
            this.text = text;
        }

        @Override
        public void onClick(Void mainEntity, List<Object> selectedItems) {
            clicked = true;
        }

        @Override
        public boolean isEnabled(Void mainEntity, List<Object> selectedItems) {
            return enabled;
        }

        @Override
        public boolean isAccessible(Void mainEntity, List<Object> selectedItems) {
            return true;
        }

        @Override
        public boolean isVisible(Void mainEntity, List<Object> selectedItems) {
            return true;
        }

        @Override
        public HasCssName getIcon() {
            return null;
        }

        @Override
        public String getText() {
            return text;
        }

        @Override
        public String getUniqueId() {
            return id;
        }

        @Override
        public void update() {
        }

        @Override
        public boolean isSubTitledAction() {
            return false;
        }

        @Override
        public SafeHtml getTooltip() {
            return null;
        }

        @Override
        public SafeHtml getMenuItemTooltip() {
            return null;
        }

        @Override
        public int getIndex() {
            return 7;
        }

        @Override
        public List<ActionButtonDefinition<Void, Object>> getSubActions() {
            return Collections.emptyList();
        }

        @Override
        public IEventListener<? super PropertyChangedEventArgs> getUpdateOnModelChangeRelevantForActionsListener() {
            return null;
        }

        @Override
        public HandlerRegistration addInitializeHandler(InitializeHandler handler) {
            return null;
        }

        @Override
        public void fireEvent(GwtEvent<?> event) {
        }
    }

    /** Nothing a cluster can be asked about, so the host count never comes into it. */
    private static final List<Object> NOT_MACHINES = Collections.singletonList("not a vm"); //$NON-NLS-1$

    @Test
    public void theMigrateButtonTheExtensionsPluginRegisters() {
        assertTrue(MigrationButtonDefinition.isMigration("MigrateVM")); //$NON-NLS-1$
        assertTrue(MigrationButtonDefinition.isMigration("Migrate")); //$NON-NLS-1$
        assertTrue(MigrationButtonDefinition.isMigration("migrate-vm-button")); //$NON-NLS-1$
        assertTrue(MigrationButtonDefinition.isMigration("Migration")); //$NON-NLS-1$
    }

    /** A deployment showing Korean has no English in the button, only in the identifier. */
    @Test
    public void theKoreanLabel() {
        assertTrue(MigrationButtonDefinition.isMigration("마이그레이션")); //$NON-NLS-1$
    }

    /** Stopping a migration already under way is not starting one. */
    @Test
    public void cancellingAMigrationIsNotMigrating() {
        assertFalse(MigrationButtonDefinition.isMigration("CancelMigrateVm")); //$NON-NLS-1$
        assertFalse(MigrationButtonDefinition.isMigration("Cancel Migration")); //$NON-NLS-1$
        assertFalse(MigrationButtonDefinition.isMigration("마이그레이션 취소")); //$NON-NLS-1$
    }

    @Test
    public void everyOtherButtonAndNothingToMatchOn() {
        assertFalse(MigrationButtonDefinition.isMigration("Console")); //$NON-NLS-1$
        assertFalse(MigrationButtonDefinition.isMigration(null));
        assertFalse(MigrationButtonDefinition.isMigration("")); //$NON-NLS-1$
    }

    @Test
    public void everyOtherPluginButtonIsHandedBackUntouched() {
        PluginButton plugins = new PluginButton("ConsoleButton", "Console"); //$NON-NLS-1$ //$NON-NLS-2$

        assertSame(plugins, MigrationButtonDefinition.asThisProductShowsIt(plugins));
    }

    /** Grey and where it was, not gone: an administrator looking for it should find it. */
    @Test
    public void everythingElseIsStillThePlugins() {
        PluginButton plugins = new PluginButton("MigrateVM", "Migrate"); //$NON-NLS-1$ //$NON-NLS-2$
        ActionButtonDefinition<Void, Object> shown =
                MigrationButtonDefinition.asThisProductShowsIt(plugins);

        assertTrue(shown.isVisible(null, NOT_MACHINES));
        assertTrue(shown.isAccessible(null, NOT_MACHINES));
        assertEquals("Migrate", shown.getText()); //$NON-NLS-1$
        assertEquals("MigrateVM", shown.getUniqueId()); //$NON-NLS-1$
        assertEquals(7, shown.getIndex());
    }

    /** With nothing to count hosts for, the plugin still decides. */
    @Test
    public void thePluginStillGetsToSayNo() {
        PluginButton plugins = new PluginButton("MigrateVM", "Migrate"); //$NON-NLS-1$ //$NON-NLS-2$
        ActionButtonDefinition<Void, Object> shown =
                MigrationButtonDefinition.asThisProductShowsIt(plugins);
        assertTrue(shown.isEnabled(null, NOT_MACHINES));

        plugins.enabled = false;
        assertFalse(shown.isEnabled(null, NOT_MACHINES));
    }

    /** A disabled button is not clicked, but a keyboard or a plugin can still reach one. */
    @Test
    public void andWhenItSaysNoTheClickDoesNothing() {
        PluginButton plugins = new PluginButton("MigrateVM", "Migrate"); //$NON-NLS-1$ //$NON-NLS-2$
        plugins.enabled = false;

        MigrationButtonDefinition.asThisProductShowsIt(plugins).onClick(null, NOT_MACHINES);

        assertFalse(plugins.clicked);
    }

    @Test
    public void andWhenItSaysYesItIsThePluginsClick() {
        PluginButton plugins = new PluginButton("MigrateVM", "Migrate"); //$NON-NLS-1$ //$NON-NLS-2$

        MigrationButtonDefinition.asThisProductShowsIt(plugins).onClick(null, NOT_MACHINES);

        assertTrue(plugins.clicked);
    }
    /** An administration application that answers what this test tells it to. */
    private static class Answering extends AsyncDataProvider {

        private Object minimum;

        private AsyncQuery<List<VDS>> outstanding;

        @Override
        public Object getConfigValuePreConverted(ConfigValues configValue) {
            return configValue == ConfigValues.MinimumHostsForMigration ? minimum : null;
        }

        @Override
        public void getHostListByClusterId(AsyncQuery<List<VDS>> aQuery, Guid clusterId) {
            outstanding = aQuery;
        }

        void answerWith(int hosts) {
            List<VDS> found = new ArrayList<>();
            for (int i = 0; i < hosts; i++) {
                found.add(new VDS());
            }
            outstanding.getAsyncCallback().onSuccess(found);
        }
    }

    private static final Guid A_CLUSTER = Guid.newGuid();

    private Answering engine;

    @BeforeEach
    public void answerAsTheseTestsSay() {
        ClusterHostCount.forget();
        engine = new Answering();
        AsyncDataProvider.setInstance(engine);
    }

    @AfterEach
    public void stopAnswering() {
        ClusterHostCount.forget();
        AsyncDataProvider.setInstance(null);
    }

    private static List<Object> oneMachineIn(Guid clusterId) {
        VM vm = new VM();
        vm.setClusterId(clusterId);
        return Collections.singletonList(vm);
    }

    private static ActionButtonDefinition<Void, Object> theMigrateButton(PluginButton plugins) {
        return MigrationButtonDefinition.asThisProductShowsIt(plugins);
    }

    /** Two hosts have nowhere to put a machine when one of them is the reason it is moving. */
    @Test
    public void greyInAClusterTooSmallToMigrateWithin() {
        engine.minimum = Integer.valueOf(3);
        ActionButtonDefinition<Void, Object> shown = theMigrateButton(new PluginButton("MigrateVM", "Migrate")); //$NON-NLS-1$ //$NON-NLS-2$
        List<Object> selected = oneMachineIn(A_CLUSTER);

        shown.isEnabled(null, selected);
        engine.answerWith(2);

        assertFalse(shown.isEnabled(null, selected));
    }

    @Test
    public void andItselfInAClusterBigEnough() {
        engine.minimum = Integer.valueOf(3);
        ActionButtonDefinition<Void, Object> shown = theMigrateButton(new PluginButton("MigrateVM", "Migrate")); //$NON-NLS-1$ //$NON-NLS-2$
        List<Object> selected = oneMachineIn(A_CLUSTER);

        shown.isEnabled(null, selected);
        engine.answerWith(3);

        assertTrue(shown.isEnabled(null, selected));
    }

    /**
     * Grey while the count is on its way. A button that starts grey and turns black misleads
     * nobody; one that starts black and turns grey invites the click it is there to prevent.
     */
    @Test
    public void andGreyUntilTheCountComesBack() {
        engine.minimum = Integer.valueOf(3);
        ActionButtonDefinition<Void, Object> shown = theMigrateButton(new PluginButton("MigrateVM", "Migrate")); //$NON-NLS-1$ //$NON-NLS-2$

        assertFalse(shown.isEnabled(null, oneMachineIn(A_CLUSTER)));
    }

    /** One machine that cannot move is enough to stop a migration of the pair of them. */
    @Test
    public void oneMachineTooManyStopsTheWholeSelection() {
        engine.minimum = Integer.valueOf(3);
        ActionButtonDefinition<Void, Object> shown = theMigrateButton(new PluginButton("MigrateVM", "Migrate")); //$NON-NLS-1$ //$NON-NLS-2$
        Guid roomy = Guid.newGuid();

        shown.isEnabled(null, oneMachineIn(roomy));
        engine.answerWith(5);
        shown.isEnabled(null, oneMachineIn(A_CLUSTER));
        engine.answerWith(2);

        List<Object> both = new ArrayList<>();
        both.addAll(oneMachineIn(roomy));
        both.addAll(oneMachineIn(A_CLUSTER));
        assertFalse(shown.isEnabled(null, both));
    }

    /** And a click that got through anyway does nothing. */
    @Test
    public void aClickInAClusterTooSmallDoesNothing() {
        engine.minimum = Integer.valueOf(3);
        PluginButton plugins = new PluginButton("MigrateVM", "Migrate"); //$NON-NLS-1$ //$NON-NLS-2$
        ActionButtonDefinition<Void, Object> shown = theMigrateButton(plugins);
        List<Object> selected = oneMachineIn(A_CLUSTER);
        shown.isEnabled(null, selected);
        engine.answerWith(2);

        shown.onClick(null, selected);

        assertFalse(plugins.clicked);
    }

    /** Every other plugin button is left to the plugin, whatever the cluster looks like. */
    @Test
    public void andNoneOfThisTouchesTheOtherButtons() {
        engine.minimum = Integer.valueOf(3);
        PluginButton plugins = new PluginButton("ConsoleButton", "Console"); //$NON-NLS-1$ //$NON-NLS-2$
        ActionButtonDefinition<Void, Object> shown = theMigrateButton(plugins);

        assertTrue(shown.isEnabled(null, oneMachineIn(A_CLUSTER)));

        shown.onClick(null, oneMachineIn(A_CLUSTER));
        assertTrue(plugins.clicked);
    }
}
