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
        return Stream.of(MockConfigDescriptor.of(ConfigValues.EnforceBlockFileSharingFilter, false));
    }

    public static Stream<MockConfigDescriptor<?>> enforced() {
        return Stream.of(MockConfigDescriptor.of(ConfigValues.EnforceBlockFileSharingFilter, true));
    }

    public static Stream<MockConfigDescriptor<?>> unset() {
        return Stream.empty();
    }

    @Test
    public void aProfileCarriesTheFilterItIsGivenAsTheEngineIsInstalled() {
        assertFalse(networkHelper.isVnicProfileNetworkFilterEnforced());
    }

    @Test
    @MockedConfig("enforced")
    public void aSiteCanDecideTheFilterIsTheOnlyOneAProfileMayHave() {
        assertTrue(networkHelper.isVnicProfileNetworkFilterEnforced());
    }

    @Test
    @MockedConfig("unset")
    public void aSettingThatIsNotThereLeavesTheEngineAsItIsInstalled() {
        // Rather than turning on something nobody asked for because a value could not be read.
        assertFalse(networkHelper.isVnicProfileNetworkFilterEnforced());
    }
}
