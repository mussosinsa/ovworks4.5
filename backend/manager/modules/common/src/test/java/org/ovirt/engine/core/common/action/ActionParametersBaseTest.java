package org.ovirt.engine.core.common.action;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Test;

public class ActionParametersBaseTest {

    @Test
    public void actionTypesUseNumericSerializedFields() throws Exception {
        assertEquals(int.class, field("parentCommand").getType());
        assertEquals(int.class, field("commandType").getType());
    }

    @Test
    public void actionTypeAccessorsRoundTripNumericFields() {
        ActionParametersBase parameters = new ActionParametersBase();

        parameters.setParentCommand(ActionType.AddDisk);
        parameters.setCommandType(ActionType.RemoveDisk);

        assertEquals(ActionType.AddDisk, parameters.getParentCommand());
        assertEquals(ActionType.RemoveDisk, parameters.getCommandType());
    }

    private Field field(String name) throws NoSuchFieldException {
        return ActionParametersBase.class.getDeclaredField(name);
    }
}
