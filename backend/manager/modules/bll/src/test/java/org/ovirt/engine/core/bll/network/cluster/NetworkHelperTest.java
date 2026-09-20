package org.ovirt.engine.core.bll.network.cluster;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.utils.MockConfigDescriptor;
import org.ovirt.engine.core.utils.MockConfigExtension;
import org.ovirt.engine.core.utils.MockedConfig;

@ExtendWith(MockConfigExtension.class)
public class NetworkHelperTest {

    private final NetworkHelper networkHelper = new NetworkHelper();

    public static Stream<MockConfigDescriptor<?>> mockConfiguration() {
        return Stream.of(MockConfigDescriptor.of(ConfigValues.EnforceBlockFileSharingFilter, true));
    }

    public static Stream<MockConfigDescriptor<?>> released() {
        return Stream.of(MockConfigDescriptor.of(ConfigValues.EnforceBlockFileSharingFilter, false));
    }

    public static Stream<MockConfigDescriptor<?>> unset() {
        return Stream.empty();
    }

    @Test
    public void theFilterIsTheOnlyOneAProfileMayHaveAsTheEngineIsInstalled() {
        assertTrue(networkHelper.isVnicProfileNetworkFilterEnforced());
    }

    @Test
    @MockedConfig("released")
    public void aSiteCanDecideItsProfilesCarryTheFilterTheyAreGiven() {
        assertFalse(networkHelper.isVnicProfileNetworkFilterEnforced());
    }

    @Test
    @MockedConfig("unset")
    public void aSettingThatIsNotThereIsTheSaferOfTheTwoRatherThanTheLooser() {
        // An engine whose configuration predates the setting keeps filtering its profiles.
        assertTrue(networkHelper.isVnicProfileNetworkFilterEnforced());
    }
}
