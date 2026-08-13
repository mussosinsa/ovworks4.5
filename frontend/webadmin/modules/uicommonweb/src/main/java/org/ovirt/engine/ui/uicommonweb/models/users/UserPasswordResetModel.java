package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;
import org.ovirt.engine.ui.uicommonweb.validation.RegexValidation;
import org.ovirt.engine.ui.uicommonweb.validation.ValidationResult;
import org.ovirt.engine.ui.uicompat.ConstantsManager;

public class UserPasswordResetModel extends Model {
    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final String MIN_LENGTH_REGEX = "^.{" + MIN_PASSWORD_LENGTH + ",}$"; //$NON-NLS-1$ //$NON-NLS-2$
    private static final String AT_LEAST_ONE_DIGIT_REGEX = ".*[0-9].*"; //$NON-NLS-1$
    private static final String AT_LEAST_ONE_UPPERCASE_REGEX = ".*[A-Z].*"; //$NON-NLS-1$
    private static final String AT_LEAST_ONE_LOWERCASE_REGEX = ".*[a-z].*"; //$NON-NLS-1$
    private static final String AT_LEAST_ONE_SPECIAL_REGEX = ".*[^A-Za-z0-9].*"; //$NON-NLS-1$

    private EntityModel<String> password;
    private String username;

    public void setUsername(String username) {
        this.username = username;
    }

    public EntityModel<String> getPassword() {
        return password;
    }

    private void setPassword(EntityModel<String> value) {
        password = value;
    }

    public UserPasswordResetModel() {
        setPassword(new EntityModel<String>());
        setTitle(ConstantsManager.getInstance().getConstants().resetPasswordTitle());
        setHashName("reset_password"); //$NON-NLS-1$
    }

    public boolean validate() {
        getPassword().validateEntity(new IValidation[] {
                new NotEmptyValidation(),
                new RegexValidation(
                        MIN_LENGTH_REGEX,
                        "패스워드는 최소 " + MIN_PASSWORD_LENGTH + "자리 이상이어야 합니다." //$NON-NLS-1$ //$NON-NLS-2$
                ),
                new RegexValidation(
                        AT_LEAST_ONE_DIGIT_REGEX,
                        "패스워드에는 숫자가 최소 1개 이상 포함되어야 합니다." //$NON-NLS-1$
                ),
                new RegexValidation(
                        AT_LEAST_ONE_UPPERCASE_REGEX,
                        "패스워드에는 영문 대문자가 최소 1개 이상 포함되어야 합니다." //$NON-NLS-1$
                ),
                new RegexValidation(
                        AT_LEAST_ONE_LOWERCASE_REGEX,
                        "패스워드에는 영문 소문자가 최소 1개 이상 포함되어야 합니다." //$NON-NLS-1$
                ),
                new RegexValidation(
                        AT_LEAST_ONE_SPECIAL_REGEX,
                        "패스워드에는 특수문자가 최소 1개 이상 포함되어야 합니다." //$NON-NLS-1$
                ),
                value -> username != null && value instanceof String && username.equalsIgnoreCase((String) value)
                        ? ValidationResult.fail("사용자 계정과 동일한 패스워드는 사용할 수 없습니다.") //$NON-NLS-1$
                        : ValidationResult.ok()
        });
        return getPassword().getIsValid();
    }
}
