package org.ovirt.engine.core.bll;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.utils.MockConfigDescriptor;
import org.ovirt.engine.core.utils.MockConfigExtension;

@ExtendWith(MockConfigExtension.class)
public class GetEngineConfigValueCommandTest {

    public static Stream<MockConfigDescriptor<?>> mockConfiguration() {
        return Stream.of(MockConfigDescriptor.of(ConfigValues.UserSessionTimeOutInterval, 30));
    }

    @Test
    public void readsValueFromLoadedEngineConfiguration() {
        assertEquals(
                "UserSessionTimeOutInterval: 30",
                GetEngineConfigValueCommand.readLoadedConfigValue("UserSessionTimeOutInterval"));
    }

    @Test
    public void rejectsUnknownConfigurationKey() {
        assertThrows(
                IllegalArgumentException.class,
                () -> GetEngineConfigValueCommand.readLoadedConfigValue("NotAnEngineConfigKey"));
    }
}
