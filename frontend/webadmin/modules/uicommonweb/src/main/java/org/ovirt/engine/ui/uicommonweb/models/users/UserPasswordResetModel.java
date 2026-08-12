package org.ovirt.engine.ui.uicommonweb.models.users;

import org.ovirt.engine.ui.uicommonweb.models.EntityModel;
import org.ovirt.engine.ui.uicommonweb.models.Model;
import org.ovirt.engine.ui.uicommonweb.validation.IValidation;
import org.ovirt.engine.ui.uicommonweb.validation.NotEmptyValidation;
import org.ovirt.engine.ui.uicommonweb.validation.RegexValidation;
import org.ovirt.engine.ui.uicompat.ConstantsManager;

/**
 * Client side pre-check of the password policy. It mirrors the mandatory part of the policy
 * so that the obvious mistakes are caught before a round trip; the authoritative check,
 * including the configurable and the reuse rules, runs in ResetUserPasswordCommand.
 */
public class UserPasswordResetModel extends Model {
    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final String MIN_LENGTH_REGEX = "^.{" + MIN_PASSWORD_LENGTH + ",}$"; //$NON-NLS-1$ //$NON-NLS-2$
    private static final String AT_LEAST_ONE_DIGIT_REGEX = ".*[0-9].*"; //$NON-NLS-1$
    private static final String AT_LEAST_ONE_UPPERCASE_REGEX = ".*[A-Z].*"; //$NON-NLS-1$
    private static final String AT_LEAST_ONE_LOWERCASE_REGEX = ".*[a-z].*"; //$NON-NLS-1$
    private static final String AT_LEAST_ONE_SPECIAL_REGEX = ".*[^A-Za-z0-9].*"; //$NON-NLS-1$

    private EntityModel<String> password;

    private String loginName;

    public EntityModel<String> getPassword() {
        return password;
    }

    private void setPassword(EntityModel<String> value) {
        password = value;
    }

    /**
     * @param loginName login name of the account whose password is being reset, used by the
     *        "password must not equal the user id" check
     */
    public void setLoginName(String loginName) {
        this.loginName = loginName;
    }

    public String getLoginName() {
        return loginName;
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
                )
        });

        if (getPassword().getIsValid() && isSameAsLoginName(getPassword().getEntity())) {
            getPassword().setIsValid(false, "패스워드를 사용자 ID와 동일하게 설정할 수 없습니다."); //$NON-NLS-1$
        }

        return getPassword().getIsValid();
    }

    private boolean isSameAsLoginName(String candidate) {
        if (candidate == null || loginName == null || loginName.isEmpty()) {
            return false;
        }
        if (candidate.equalsIgnoreCase(loginName)) {
            return true;
        }
        int separator = loginName.indexOf('@');
        return separator > 0 && candidate.equalsIgnoreCase(loginName.substring(0, separator));
    }
}
