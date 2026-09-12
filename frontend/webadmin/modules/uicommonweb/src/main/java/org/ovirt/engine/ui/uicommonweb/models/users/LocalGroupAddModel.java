package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;
import org.ovirt.engine.ui.uicommonweb.validation.RegexValidation;

/**
 * The group an administrator is creating in the internal authorization provider.
 *
 * <p>A group has a name and nothing else to decide - no password, no first and last name - so this
 * is the whole of it.</p>
 */
public class LocalGroupAddModel extends Model {

    /** What the provider's own tool accepts as a name. */
    private static final String NAME_PATTERN = "^[A-Za-z0-9._-]+$"; //$NON-NLS-1$

    private final EntityModel<String> groupName = new EntityModel<>();

    public EntityModel<String> getGroupName() {
        return groupName;
    }

    /**
     * Checks the name before the dialog is submitted. The engine checks it again in
     * AddLocalGroupCommand, which is the authority; this only saves the round trip.
     */
    public boolean validate() {
        RegexValidation name = new RegexValidation();
        name.setExpression(NAME_PATTERN);
        name.setMessage("이름에는 영문, 숫자, 점, 밑줄, 붙임표만 쓸 수 있습니다."); //$NON-NLS-1$

        groupName.validateEntity(new IValidation[] { new NotEmptyValidation(), name });
        return groupName.getIsValid();
    }
}
