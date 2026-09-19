package org.ovirt.engine.ui.common.widget.action;

import java.util.List;

import org.ovirt.engine.core.common.businessentities.VM;
import org.ovirt.engine.ui.uicompat.IEventListener;
import org.ovirt.engine.ui.uicompat.PropertyChangedEventArgs;

import com.google.gwt.dom.client.Style.HasCssName;
import com.google.gwt.event.logical.shared.InitializeHandler;
import com.google.gwt.event.shared.GwtEvent;
import com.google.gwt.event.shared.HandlerRegistration;
import com.google.gwt.safehtml.shared.SafeHtml;

/**
 * The migration button, as this product shows it: there, and not enabled in a cluster too small to
 * migrate within.
 *
 * <p>The button is not in this source. It is registered by ovirt-engine-ui-extensions, a separate
 * package this one requires, and it is built and drawn here from what that plugin hands over. So
 * there is no command in this code to refuse; what there is, is the moment the plugin's button is
 * built, and that is where this takes hold of it.</p>
 *
 * <p>Everything else stays the plugin's - the text, the icon, where it sits, whether the user may
 * see it at all. Only being clickable is taken away, and clicking is the one thing a button that
 * should not be used must not do.</p>
 *
 * <p>The engine refuses the migration too - see MigrateVmCommand and MinimumHostsForMigration.
 * That is the rule; this is the button. A rule only the engine knows makes an administrator click
 * to find out, and a rule only a screen knows is a rule about the screen.</p>
 *
 * @param <E> main tab table item type, or {@code Void}
 * @param <T> action panel item type
 */
public class MigrationButtonDefinition<E, T> implements ActionButtonDefinition<E, T> {

    /**
     * What a migration button is called, in the identifier or in the label.
     *
     * <p>Lower case, and compared against a lower cased identifier and label, so that Migrate,
     * MigrateVm and migrate-vm are all the same thing. The identifier is the plugin's own and this
     * product does not set it, so matching the label as well is what keeps the decision from
     * resting on a name in another repository staying what it is. The Korean label is here because
     * a deployment showing Korean has no English in the button at all.</p>
     */
    private static final String[] MIGRATION = { "migrate", "migration", "마이그레이션" }; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

    /**
     * What names a migration but is not one to start.
     *
     * <p>Cancelling a migration already under way is the opposite of starting one, and a machine
     * half moved is exactly when an administrator needs it. It carries the word all the same.</p>
     */
    private static final String[] NOT_STARTING_ONE = { "cancel", "취소" }; //$NON-NLS-1$ //$NON-NLS-2$

    private final ActionButtonDefinition<E, T> delegate;

    MigrationButtonDefinition(ActionButtonDefinition<E, T> delegate) {
        this.delegate = delegate;
    }

    /**
     * @param definition a button a UI plugin has just asked for
     * @return it, or the same button with the migration rule over it
     *
     * <p>Called where plugin buttons are built rather than where they are drawn: they are drawn
     * from several places, and a button that arrives while its tab is already open skips one of
     * them entirely. Built once, though, is built once.</p>
     */
    public static <E, T> ActionButtonDefinition<E, T> asThisProductShowsIt(
            ActionButtonDefinition<E, T> definition) {
        return isMigration(definition.getUniqueId()) || isMigration(definition.getText())
                ? new MigrationButtonDefinition<>(definition)
                : definition;
    }

    /**
     * @param value an identifier or a label, or null when the plugin gave none
     * @return whether it names the action that starts a migration
     */
    static boolean isMigration(String value) {
        if (value == null || value.isEmpty()) {
            return false;
        }
        String lowered = value.toLowerCase();
        return contains(lowered, MIGRATION) && !contains(lowered, NOT_STARTING_ONE);
    }

    private static boolean contains(String lowered, String[] names) {
        for (String name : names) {
            if (lowered.contains(name)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Enabled only once every selected machine is known to sit in a cluster with hosts enough to
     * migrate within.
     *
     * <p>Not yet known counts as not enough: the count is asked for the first time a button is
     * drawn and comes back in the moment after, and a button that starts grey and turns black
     * misleads nobody, where one that starts black and turns grey invites the click it is there
     * to prevent.</p>
     */
    @Override
    public boolean isEnabled(E mainEntity, List<T> selectedItems) {
        return enoughHosts(selectedItems) && delegate.isEnabled(mainEntity, selectedItems);
    }

    private boolean enoughHosts(List<T> selectedItems) {
        if (selectedItems == null) {
            return true;
        }
        for (T item : selectedItems) {
            if (item instanceof VM) {
                Boolean enough = ClusterHostCount.enoughToMigrateWithin(((VM) item).getClusterId(),
                        delegate::update);
                if (!Boolean.TRUE.equals(enough)) {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Does nothing when the button should not be used.
     *
     * <p>A disabled button is not clicked, but a keyboard or the plugin's own code can still reach
     * one, and the engine refusing it afterwards is an error message where there should have been
     * nothing at all.</p>
     */
    @Override
    public void onClick(E mainEntity, List<T> selectedItems) {
        if (isEnabled(mainEntity, selectedItems)) {
            delegate.onClick(mainEntity, selectedItems);
        }
    }

    @Override
    public boolean isAccessible(E mainEntity, List<T> selectedItems) {
        return delegate.isAccessible(mainEntity, selectedItems);
    }

    @Override
    public boolean isVisible(E mainEntity, List<T> selectedItems) {
        return delegate.isVisible(mainEntity, selectedItems);
    }

    @Override
    public HasCssName getIcon() {
        return delegate.getIcon();
    }

    @Override
    public String getText() {
        return delegate.getText();
    }

    @Override
    public String getUniqueId() {
        return delegate.getUniqueId();
    }

    @Override
    public void update() {
        delegate.update();
    }

    @Override
    public boolean isSubTitledAction() {
        return delegate.isSubTitledAction();
    }

    @Override
    public SafeHtml getTooltip() {
        return delegate.getTooltip();
    }

    @Override
    public SafeHtml getMenuItemTooltip() {
        return delegate.getMenuItemTooltip();
    }

    @Override
    public int getIndex() {
        return delegate.getIndex();
    }

    @Override
    public List<ActionButtonDefinition<E, T>> getSubActions() {
        return delegate.getSubActions();
    }

    @Override
    public IEventListener<? super PropertyChangedEventArgs> getUpdateOnModelChangeRelevantForActionsListener() {
        return delegate.getUpdateOnModelChangeRelevantForActionsListener();
    }

    @Override
    public HandlerRegistration addInitializeHandler(InitializeHandler handler) {
        return delegate.addInitializeHandler(handler);
    }

    @Override
    public void fireEvent(GwtEvent<?> event) {
        delegate.fireEvent(event);
    }
}
