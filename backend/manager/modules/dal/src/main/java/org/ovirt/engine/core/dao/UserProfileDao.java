// Modified by 새올정보기술 for OV-Works (2026). Changes against oVirt Engine 4.5.6: docs/ovworks-source-change-statement.md
package org.ovirt.engine.core.dao;

import java.util.List;

import org.ovirt.engine.core.common.businessentities.UserProfile;
import org.ovirt.engine.core.common.businessentities.UserProfileProperty;
import org.ovirt.engine.core.common.businessentities.UserSshKey;
import org.ovirt.engine.core.compat.Guid;

public interface UserProfileDao extends Dao {

    UserProfileProperty get(Guid propertyId);

    Guid save(UserProfileProperty property);

    UserProfileProperty update(UserProfileProperty property);

    void remove(Guid keyId);

    List<UserProfileProperty> getAll(Guid userId);

    UserProfile getProfile(Guid userId);

    List<UserSshKey> getAllPublicSshKeys();

    UserProfileProperty getByName(String name, Guid userId);

    /** Every user's property of the given name. */
    List<UserProfileProperty> getAllByName(String name);
}
